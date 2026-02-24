# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with ODTU Group Sync (Login-Only)
# version: 6.0.2
# authors: Jon Bake <jonmbake@gmail.com>, ODTU Customization

enabled_site_setting :ldap_enabled

# Ruby 3.4 Uyumlu Gem Surumleri (500 Hatasi Cozumu)
gem 'net-ldap', '0.19.0'
gem 'pyu-ruby-sasl', '0.0.3.3', require: false
gem 'rubyntlm', '0.3.4', require: false
gem 'omniauth-ldap', '2.2.0' # OmniAuth LDAP'in en guncel surumu!

require 'yaml'
require_relative 'lib/omniauth-ldap/adaptor'
require_relative 'lib/omniauth/strategies/ldap'
require_relative 'lib/ldap_user'

# =============================================================
# ODTU GRUP SENKRONIZASYON MODULU (AKILLI EKLEME/CIKARMA)
# =============================================================
module LDAPGroupSync
  def self.sync(user)
    u_type  = user.custom_fields['ldap_type']
    u_minor = user.custom_fields['ldap_minor']
    u_major = user.custom_fields['ldap_major']

    rules = [
      { group: "A-OGRENCI-DUYURU", type: { allow: [16, 4, 25] }, minor: nil, major: nil },
      { group: "LISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['bs'] }, major: nil },
      { group: "YUKSEKLISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms'] }, major: nil },
      { group: "DOKTORA-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['phd'] }, major: nil },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['adm', 'dns'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "A-OGR-UYE-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "A-OGR-ELM-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "A-OGR-ELM-DUYURU", type: { deny: [27] }, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "T-OGR-UYE-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "T-OGR-ELM-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "T-OGR-ELM-DUYURU", type: { deny: [27] }, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "ARAS-GOR-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "OGR-UYE-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "OGRENCI-DUYURU", type: { allow: [16, 4, 25, 26, 42] }, minor: nil, major: nil },
      { group: "LISANSUSTU-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms', 'phd'] }, major: nil },
      { group: "EMEKLI-DUYURU", type: { allow: [28] }, minor: nil, major: nil },
      { group: "AKADEMIK-EMEKLI-DUYURU", type: { allow: [28] }, minor: { allow: ['aca'] }, major: nil }
    ]

    rules.each do |rule|
      match_type  = check_match(u_type, rule[:type] ? rule[:type][:allow] : nil, rule[:type] ? rule[:type][:deny] : nil)
      match_minor = check_match(u_minor, rule[:minor] ? rule[:minor][:allow] : nil, rule[:minor] ? rule[:minor][:deny] : nil)
      match_major = check_match(u_major, rule[:major] ? rule[:major][:allow] : nil, rule[:major] ? rule[:major][:deny] : nil)

      group = Group.find_or_create_by(name: rule[:group])
      
      if match_type && match_minor && match_major
        unless group.users.include?(user)
          group.add(user)
          group.save
        end
      else
        if group.users.include?(user)
          group.remove(user)
          group.save
        end
      end
    end
  end

  def self.check_match(user_value, allowed_list, excluded_list)
    return true if allowed_list.nil? && excluded_list.nil?
    return false if user_value.nil?
    raw_values = user_value.is_a?(Array) ? user_value : [user_value]
    user_values_norm = raw_values.map { |v| v.to_s.downcase.strip }
    if excluded_list
      excluded_norm = excluded_list.map { |v| v.to_s.downcase.strip }
      return false unless (user_values_norm & excluded_norm).empty?
    end
    if allowed_list
      allowed_norm = allowed_list.map { |v| v.to_s.downcase.strip }
      return false if (user_values_norm & allowed_norm).empty?
    end
    return true
  end
end

# =============================================================
# AUTHENTICATOR
# =============================================================
# rubocop:disable Discourse/Plugins/NoMonkeyPatching
class ::LDAPAuthenticator < ::Auth::Authenticator
  def name
    'ldap'
  end

  def enabled?
    true
  end

  def register_middleware(omniauth)
    omniauth.configure{ |c| c.form_css = File.read(File.expand_path("../css/form.css", __FILE__)) }
    omniauth.provider :ldap,
      setup:  -> (env) {
        env["omniauth.strategy"].options.merge!(
          host: SiteSetting.ldap_hostname,
          port: SiteSetting.ldap_port,
          method: SiteSetting.ldap_method,
          base: SiteSetting.ldap_base,
          uid: SiteSetting.ldap_uid,
          bind_dn: SiteSetting.ldap_bind_dn.presence || SiteSetting.try(:ldap_bind_db),
          password: SiteSetting.ldap_password,
          filter: SiteSetting.ldap_filter,
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major', 'memberof', 'fname'],
          mapping: { email: 'uemail' }
        )
      }
  end

  def after_authenticate(auth_options)
    result = auth_result(auth_options)

    ldap_data = {}
    if auth_options.extra && auth_options.extra[:raw_info]
      raw = auth_options.extra[:raw_info]
      extract_val = ->(key) {
        val = raw[key] || raw[key.to_s]
        final = val.respond_to?(:first) ? val.first : val
        final.to_s.strip
      }
      ldap_data[:type]  = extract_val.call(:type)
      ldap_data[:minor] = extract_val.call(:minor)
      ldap_data[:major] = extract_val.call(:major)

      ldap_name = extract_val.call(:cn)
      if ldap_name.empty?
        fname = extract_val.call(:fname)
        sname = extract_val.call(:sn)
        ldap_name = "#{fname} #{sname}".strip
      end
      ldap_data[:fullname] = ldap_name
    end

    if result.email.nil? || result.email.empty?
      candidate = extract_val.call(:uemail) if extract_val
      candidate ||= extract_val.call(:mail) if extract_val
      if candidate && !candidate.empty?
        result.email = candidate
        result.email_valid = true
      end
    end

    if result.user
      result.user.custom_fields['ldap_type']  = ldap_data[:type]
      result.user.custom_fields['ldap_minor'] = ldap_data[:minor]
      result.user.custom_fields['ldap_major'] = ldap_data[:major]
      result.user.save_custom_fields
      
      if ldap_data[:fullname] && !ldap_data[:fullname].empty?
        if result.user.name != ldap_data[:fullname]
          result.user.name = ldap_data[:fullname]
          result.user.save
        end
      end
      
      LDAPGroupSync.sync(result.user)
    else
      if result.email
        PluginStore.set('ldap', "pending_#{result.email}", ldap_data)
      end
    end

    result
  end

  private
   
  def auth_result(auth)
    auth_info = auth.info
    extra_info = auth.extra || {}
    raw_info = extra_info[:raw_info] || {}
    
    if raw_info.respond_to?(:to_hash)
       raw_info = raw_info.to_hash
    end

    if (auth_info[:email].nil? || auth_info[:email].empty?)
      uemail_val = raw_info['uemail'] || raw_info[:uemail]
      if uemail_val
        ldap_mail = uemail_val.kind_of?(Array) ? uemail_val.first : uemail_val
        auth_info[:email] = ldap_mail if ldap_mail
      end
    end
    
    result = Auth::Result.new
    if auth.info[:email] && user = User.find_by_email(auth.info[:email])
        result.user = user
    end
    
    if result.user.nil?
        case SiteSetting.ldap_user_create_mode
        when 'auto'
            result = LDAPUser.new(auth_info).auth_result
        when 'none'
            ldap_user = LDAPUser.new(auth_info)
            ldap_user.account_exists? ? ldap_user.auth_result : fail_auth('User account does not exist.')
        when 'list'
             fail_auth('List mode not implemented.')
        end
    end
    
    if (result.email.nil? || result.email.empty?) && auth.info[:email]
        result.email = auth.info[:email]
        result.email_valid = true
    end
    
    result
  end

  def fail_auth(reason)
    result = Auth::Result.new
    result.failed = true
    result.failed_reason = reason
    result
  end
end
# rubocop:enable Discourse/Plugins/NoMonkeyPatching

auth_provider authenticator: LDAPAuthenticator.new

register_css <<CSS
  .btn {
    &.ldap {
      background-color: #517693;
    }
  }
CSS

after_initialize do
  on(:user_created) do |user|
    if pending_data = PluginStore.get('ldap', "pending_#{user.email}")
      user.custom_fields['ldap_type']  = pending_data[:type]
      user.custom_fields['ldap_minor'] = pending_data[:minor]
      user.custom_fields['ldap_major'] = pending_data[:major]
      user.save_custom_fields

      if pending_data[:fullname] && !pending_data[:fullname].empty?
        user.name = pending_data[:fullname]
        user.save
      end
      
      LDAPGroupSync.sync(user)
      PluginStore.remove('ldap', "pending_#{user.email}")
    end
  end
end

# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with Group Sync (Hybrid Stable Version)
# version: 4.0.0

enabled_site_setting :ldap_enabled

gem 'pyu-ruby-sasl', '0.0.3.3', require: false
gem 'rubyntlm', '0.3.4', require: false
gem 'net-ldap', '0.18.0'

require 'yaml'
require_relative 'lib/omniauth-ldap/adaptor'
require_relative 'lib/omniauth/strategies/ldap'
require_relative 'lib/ldap_user'

# rubocop:disable Discourse/Plugins/NoMonkeyPatching
class ::LDAPAuthenticator < ::Auth::Authenticator
  def name
    'ldap'
  end

  def enabled?
    true
  end

  # =============================================================
  # 1. GIRIS ISLEMI (Sizin Calisan Kodunuzun Uzerine Kuruldu)
  # =============================================================
  def after_authenticate(auth_options)
    Rails.logger.warn("LDAP_LOG: === after_authenticate BASLADI (v4.0 Hybrid) ===")

    # 1. Standart islemi calistir (Email kurtarma icerde yapiliyor)
    result = auth_result(auth_options)

    # Kullanici yoksa islem yapma
    unless result.user
      Rails.logger.warn("LDAP_LOG: Kullanici olusturulamadi (User=nil).")
      return result
    end

    # 2. Custom Fields ve Gruplar icin Veri Hazirligi
    # Sizin calisan kodunuzdaki mantik: Hash cevirme yok, direkt erisim var.
    if auth_options.extra && auth_options.extra[:raw_info]
      raw = auth_options.extra[:raw_info]
      
      # Helper: Sizin kodunuzdaki calisan veri okuma yöntemi
      extract_val = ->(key) {
        val = raw[key] || raw[key.to_s]
        # Array ise ilkini al, degilse kendisini
        val.respond_to?(:first) ? val.first : val
      }

      # Custom Fields Guncelle
      result.user.custom_fields['ldap_type']  = extract_val.call(:type).to_s
      result.user.custom_fields['ldap_minor'] = extract_val.call(:minor).to_s
      result.user.custom_fields['ldap_major'] = extract_val.call(:major).to_s
      
      result.user.save_custom_fields
      Rails.logger.warn("LDAP_LOG: Custom fields guncellendi: #{result.user.username}")

      # 3. GRUP SENKRONIZASYONU (YENI EKLENEN KISIM)
      sync_groups_based_on_rules(result.user)
    else
      Rails.logger.warn("LDAP_LOG: Raw info bulunamadi, grup islemleri atlandi.")
    end

    Rails.logger.warn("LDAP_LOG: === after_authenticate BITTI ===")
    result
  end

  # =============================================================
  # 2. GRUP SENKRONIZASYON MANTIGI
  # =============================================================
  def sync_groups_based_on_rules(user)
    Rails.logger.warn("LDAP_LOG: Grup kurallari calistiriliyor...")

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

      if match_type && match_minor && match_major
        group = Group.find_or_create_by(name: rule[:group])
        unless group.users.include?(user)
          group.add(user)
          group.save
          Rails.logger.warn("LDAP_LOG: [Group Sync] EKLE: #{user.username} -> #{rule[:group]}")
        end
      end
    end
  end

  def check_match(user_value, allowed_list, excluded_list)
    return true if allowed_list.nil? && excluded_list.nil?
    return false if user_value.nil?
    user_values = user_value.is_a?(Array) ? user_value.map(&:to_s) : [user_value.to_s]
    if excluded_list
      return false unless (user_values & excluded_list.map(&:to_s)).empty?
    end
    if allowed_list
      return (user_values & allowed_list.map(&:to_s)).any?
    end
    return true
  end

  # =============================================================
  # 3. MIDDLEWARE CONFIG (MemberOf Eklendi)
  # =============================================================
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
          # 'memberof' eklemeyi unutmuyoruz
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major', 'memberof'],
          mapping: { email: 'uemail' }
        )
      }
  end

  private
   
  # =============================================================
  # 4. AUTH RESULT (Sizin Calisan Kodunuz)
  # =============================================================
  def auth_result(auth)
    # Paketi parcalara ayir
    auth_info = auth.info
    extra_info = auth.extra || {}
    raw_info = extra_info[:raw_info] || {}

    # Email Kurtarma: Sizin calisan kodunuzdaki mantik
    if (auth_info[:email].nil? || auth_info[:email].empty?) && raw_info['uemail']
      Rails.logger.warn("LDAP: Standart email bos. 'uemail' alanindan veri kurtariliyor...")
      
      # Array veya string kontrolu
      ldap_mail = raw_info['uemail'].kind_of?(Array) ? raw_info['uemail'].first : raw_info['uemail']
      
      if ldap_mail
        auth_info[:email] = ldap_mail
        Rails.logger.warn("LDAP: Email basariyla kurtarildi: #{ldap_mail}")
      end
    end

    case SiteSetting.ldap_user_create_mode
      when 'none'
        ldap_user = LDAPUser.new(auth_info)
        ldap_user.account_exists? ? ldap_user.auth_result : fail_auth('User account does not exist.')
      when 'list'
        user_descriptions = load_user_descriptions
        return fail_auth('List of users must be provided when ldap_user_create_mode setting is set to \'list\'.') if user_descriptions.nil?
        match = user_descriptions.find { |ud|  auth_info[:email].casecmp(ud[:email]) == 0 }
        return fail_auth('User with email is not listed in LDAP user list.') if match.nil?
        match[:nickname] = match[:username] || auth_info[:nickname]
        match[:name] = match[:name] || auth_info[:name]
        LDAPUser.new(match).auth_result
      when 'auto'
        LDAPUser.new(auth_info).auth_result
      else
        fail_auth('Invalid option for ldap_user_create_mode setting.')
    end
  end

  def fail_auth(reason)
    result = Auth::Result.new
    result.failed = true
    result.failed_reason = reason
    result
  end

  def load_user_descriptions
    file_path = "#{File.expand_path(File.dirname(__FILE__))}/ldap_users.yml"
    return nil unless File.exist?(file_path)
    YAML.load_file(file_path)
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

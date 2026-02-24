# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with First-Login Group Sync (v5.0 - Fixed Init)
# version: 5.0.1

enabled_site_setting :ldap_enabled

gem 'net-ldap', '0.19.0' # 0.18.0'dan 0.19.0'a yukselttik
gem 'pyu-ruby-sasl', '0.0.3.3', require: false
gem 'rubyntlm', '0.3.4', require: false

# EGER kconv veya nkf hatasi devam ederse diye onlemler:
gem 'nkf', '0.2.0'

# =============================================================
# GRUP SENKRONIZASYON MODULU (Ortak Kullanim Icin)
# =============================================================
module LDAPGroupSync
  def self.sync(user)
    Rails.logger.warn("LDAP_SYNC: [#{user.username}] Grup kurallari calistiriliyor...")

    u_type  = user.custom_fields['ldap_type']
    u_minor = user.custom_fields['ldap_minor']
    u_major = user.custom_fields['ldap_major']

    rules = [
      # OGRENCI GRUPLARI
      { group: "A-OGRENCI-DUYURU", type: { allow: [16, 4, 25] }, minor: nil, major: nil },
      { group: "LISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['bs'] }, major: nil },
      { group: "YUKSEKLISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms'] }, major: nil },
      { group: "DOKTORA-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['phd'] }, major: nil },
      
      # GENEL
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['adm', 'dns'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },

      # PERSONEL
      { group: "A-OGR-UYE-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "A-OGR-ELM-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "A-OGR-ELM-DUYURU", type: { deny: [27] }, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      
      # TEKNIK
      { group: "T-OGR-UYE-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "T-OGR-ELM-DUYURU", type: { deny: [27, 2, 3, 33] }, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "T-OGR-ELM-DUYURU", type: { deny: [27] }, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },

      # DIGER
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
          Rails.logger.warn("LDAP_SYNC: [EKLE] #{user.username} -> #{rule[:group]}")
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
# AUTHENTICATOR CLASS
# =============================================================
# rubocop:disable Discourse/Plugins/NoMonkeyPatching
class ::LDAPAuthenticator < ::Auth::Authenticator
  def name
    'ldap'
  end

  def enabled?
    true
  end

  def after_authenticate(auth_options)
    Rails.logger.warn("LDAP_LOG: === after_authenticate (v5.0.1) ===")
    
    result = auth_result(auth_options)

    # Veri Hazirligi
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
    end

    # E-posta Force Fix
    if result.email.nil? || result.email.empty?
      Rails.logger.warn("LDAP_LOG: Email bos, manuel kurtariliyor...")
      candidate = extract_val.call(:uemail) if extract_val
      candidate ||= extract_val.call(:mail) if extract_val
      
      if candidate && !candidate.empty?
        result.email = candidate
        result.email_valid = true
        Rails.logger.warn("LDAP_LOG: Email kurtarildi: #{result.email}")
      end
    end

    if result.user
      # 1. MEVCUT KULLANICI: Hemen işle
      Rails.logger.warn("LDAP_LOG: Mevcut kullanici. Guncelleniyor...")
      result.user.custom_fields['ldap_type']  = ldap_data[:type]
      result.user.custom_fields['ldap_minor'] = ldap_data[:minor]
      result.user.custom_fields['ldap_major'] = ldap_data[:major]
      result.user.save_custom_fields
      
      LDAPGroupSync.sync(result.user)
    else
      # 2. YENI KULLANICI: Veriyi PluginStore'a sakla (Email anahtarı ile)
      if result.email
        Rails.logger.warn("LDAP_LOG: Yeni kullanici kaydi bekleniyor. Veriler PluginStore'a saklaniyor: #{result.email}")
        PluginStore.set('ldap', "pending_#{result.email}", ldap_data)
      else
        Rails.logger.warn("LDAP_LOG: HATA! Email olmadigi icin veri saklanamadi.")
      end
    end

    Rails.logger.warn("LDAP_LOG: === Bitti ===")
    result
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
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major', 'memberof'],
          mapping: { email: 'uemail' }
        )
      }
  end

  private
   
  def auth_result(auth)
    auth_info = auth.info
    extra_info = auth.extra || {}
    raw_info = extra_info[:raw_info] || {}
    
    # Raw Info Hash Cevirimi
    if raw_info.respond_to?(:to_hash)
       raw_info = raw_info.to_hash
    end

    # Email Kurtarma
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

# =============================================================
# EVENT LISTENER: YENI KULLANICI OLUSTUGUNDA TETIKLENIR
# =============================================================
# DIKKAT: Rebuild db:migrate asamasinin cokmemesi icin after_initialize icine alindi
after_initialize do
  on(:user_created) do |user|
    # PluginStore'da bu email icin bekleyen LDAP verisi var mi?
    if pending_data = PluginStore.get('ldap', "pending_#{user.email}")
      Rails.logger.warn("LDAP_EVENT: Yeni kullanici (#{user.username}) icin bekleyen veri bulundu. Isleniyor...")
      
      user.custom_fields['ldap_type']  = pending_data[:type]
      user.custom_fields['ldap_minor'] = pending_data[:minor]
      user.custom_fields['ldap_major'] = pending_data[:major]
      user.save_custom_fields
      
      # Gruplari Senkronize Et
      LDAPGroupSync.sync(user)
      
      # Temizlik: Veriyi sil
      PluginStore.remove('ldap', "pending_#{user.email}")
      Rails.logger.warn("LDAP_EVENT: Islem tamamlandi ve gecici veri silindi.")
    end
  end
end

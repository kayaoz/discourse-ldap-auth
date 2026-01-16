# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with Rule-Based Group Sync & Force Email
# version: 3.0.0

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

  # =========================================================
  # 1. GIRIS SONRASI ISLEMLER (AFTER AUTHENTICATE)
  # =========================================================
  def after_authenticate(auth_options)
    Rails.logger.warn("LDAP_LOG: === after_authenticate BASLADI (v3.0) ===")
    
    # 1. Auth sonucunu al
    result = auth_result(auth_options)

    # 2. LDAP Verisini Standart Hash'e Cevir
    raw_info = {}
    if auth_options.extra && auth_options.extra[:raw_info]
      data = auth_options.extra[:raw_info]
      if data.respond_to?(:to_hash)
        raw_info = data.to_hash
      elsif data.kind_of?(Hash)
        raw_info = data
      end
    end

    # Helper: Veri okuma
    get_val = ->(key) {
      val = raw_info[key] || raw_info[key.to_s]
      val.respond_to?(:first) ? val.first : val
    }

    # Debug: E-posta durumu
    Rails.logger.warn("LDAP_LOG: Result Email Durumu: #{result.email.inspect}")
    Rails.logger.warn("LDAP_LOG: Gelen Raw Keys: #{raw_info.keys rescue 'yok'}")

    # =========================================================
    # ACIL YAMA: Eger result.email hala bossa, burada zorla doldur
    # =========================================================
    if result.email.nil? || result.email.empty?
      Rails.logger.warn("LDAP_LOG: UYARI! Email bos. Manuel kurtarma deneniyor...")
      
      candidate_email = get_val.call(:uemail) || get_val.call(:mail)
      
      if candidate_email && !candidate_email.to_s.empty?
        result.email = candidate_email.to_s
        result.email_valid = true
        Rails.logger.warn("LDAP_LOG: KURTARILDI! Email result'a zorla yazildi: #{result.email}")
      else
        Rails.logger.warn("LDAP_LOG: KRITIK HATA! Email hicbir yerden bulunamadi.")
      end
    end

    # 3. Kullanici Varsa -> Gruplari ve Alanlari Guncelle
    if result.user
      # Custom Fields
      result.user.custom_fields['ldap_type']  = get_val.call(:type).to_s
      result.user.custom_fields['ldap_major'] = get_val.call(:major).to_s
      result.user.custom_fields['ldap_minor'] = get_val.call(:minor).to_s
      result.user.save_custom_fields
      
      Rails.logger.warn("LDAP_LOG: Custom fields guncellendi.")

      # Grup Senkronizasyonu
      sync_groups_based_on_rules(result.user)
    else
      Rails.logger.warn("LDAP_LOG: Kullanici henuz olusmadi (User=nil). Kayit ekranina yonlendiriliyor.")
    end

    Rails.logger.warn("LDAP_LOG: === after_authenticate BITTI ===")
    result
  end

  # =========================================================
  # 2. GRUP SENKRONIZASYON MANTIGI
  # =========================================================
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
      
      # GENEL GRUPLAR
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

  # =========================================================
  # 3. MIDDLEWARE CONFIG
  # =========================================================
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
   
  # =========================================================
  # 4. AUTH RESULT (ÖZEL)
  # =========================================================
  def auth_result(auth)
    # 1. Gelen ham veriyi hash'e cevir
    raw_info = {}
    if auth.extra && auth.extra[:raw_info]
      data = auth.extra[:raw_info]
      if data.respond_to?(:to_hash)
        raw_info = data.to_hash
      elsif data.kind_of?(Hash)
        raw_info = data
      end
    end

    # 2. ODTU YAMASI: auth.info[:email] bos ise uemail'den doldur
    # Bu adim kritik! result objesi olusmadan ONCE yapilmali.
    if auth.info[:email].nil? || auth.info[:email].to_s.empty?
       # uemail Array veya String olabilir
       uemail_val = raw_info['uemail'] || raw_info[:uemail]
       
       if uemail_val
         # Array ise ilkini al
         final_email = uemail_val.kind_of?(Array) ? uemail_val.first : uemail_val
         if final_email && !final_email.to_s.empty?
            auth.info[:email] = final_email.to_s
            Rails.logger.warn("LDAP_LOG: (auth_result) Email 'uemail' alanindan auth.info'ya kopyalandi: #{final_email}")
         end
       end
    end
    
    # 3. Standart Discourse Akisi
    result = Auth::Result.new
    
    # Kullaniciyi email ile bulmayi dene
    if auth.info[:email] && user = User.find_by_email(auth.info[:email])
        result.user = user
    end
    
    # Kullanici yoksa olusturma mantigi
    if result.user.nil?
        case SiteSetting.ldap_user_create_mode
        when 'auto'
            result = LDAPUser.new(auth.info).auth_result
        when 'none'
            ldap_user = LDAPUser.new(auth.info)
            ldap_user.account_exists? ? ldap_user.auth_result : fail_auth('User account does not exist.')
        when 'list'
             fail_auth('List mode not implemented.')
        end
    end
    
    # 4. SON KONTROL: Eger result donuyor ama email eksikse, auth.info'dan tekrar zorla
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

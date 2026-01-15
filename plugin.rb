# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with Rule-Based Group Sync (Fixed)
# version: 2.1.0

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
    puts "\n=========================================="
    puts "=== LDAP AUTH BASLADI ==="
    
    # 1. Auth sonucunu al (Email kurtarma dahil)
    result = auth_result(auth_options)

    # 2. Kullanici olusmadiysa veya bulunamadiysa dur
    unless result.user
      puts ">> HATA: Kullanici bulunamadigi icin islem yapilamadi."
      return result
    end

    # 3. LDAP Verisini Standart Hash'e Cevir (FIX BURADA)
    raw_info = {}
    if auth_options.extra && auth_options.extra[:raw_info]
      data = auth_options.extra[:raw_info]
      # Net::LDAP::Entry nesnesini Hash'e ceviriyoruz
      if data.respond_to?(:to_hash)
        raw_info = data.to_hash
      elsif data.kind_of?(Hash)
        raw_info = data
      end
    end

    # Debug Logu (Artik patlamaz)
    puts ">> LDAP DEBUG: Gelen Veri Anahtarlari: #{raw_info.keys rescue 'Hata'}"

    # 4. Custom Fields Kaydi
    # Helper: Veriyi guvenli okuma
    get_val = ->(key) {
      val = raw_info[key] || raw_info[key.to_s]
      val.respond_to?(:first) ? val.first : val
    }
      
    result.user.custom_fields['ldap_type']  = get_val.call(:type).to_s
    result.user.custom_fields['ldap_major'] = get_val.call(:major).to_s
    result.user.custom_fields['ldap_minor'] = get_val.call(:minor).to_s
      
    result.user.save_custom_fields
    puts ">> Custom Fields Guncellendi: Type=#{result.user.custom_fields['ldap_type']}, Major=#{result.user.custom_fields['ldap_major']}"

    # 5. GRUP SENKRONIZASYONU (Rules Engine)
    sync_groups_based_on_rules(result.user)

    puts "=== LDAP AUTH BITTI ==="
    puts "==========================================\n"

    result
  end

  # =========================================================
  # 2. GRUP SENKRONIZASYON MANTIGI (RULES ENGINE)
  # =========================================================
  def sync_groups_based_on_rules(user)
    puts ">> [LDAP Group Sync] Kurallar calistiriliyor..."

    u_type  = user.custom_fields['ldap_type']
    u_minor = user.custom_fields['ldap_minor']
    u_major = user.custom_fields['ldap_major']

    # SIZIN BELIRLEDIGINIZ KURALLAR LISTESI
    rules = [
      # A-OGRENCI-DUYURU
      { group: "A-OGRENCI-DUYURU", type: { allow: [16, 4, 25] }, minor: nil, major: nil },
      
      # LISANS / YUKSEK / DOKTORA
      { group: "LISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['bs'] }, major: nil },
      { group: "YUKSEKLISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms'] }, major: nil },
      { group: "DOKTORA-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['phd'] }, major: nil },

      # GENEL-DUYURU (Minor allow OR Minor allow OR Minor allow... seklinde)
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['adm', 'dns'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },

      # PERSONEL GRUPLARI
      { 
        group: "A-OGR-UYE-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },
      { 
        group: "A-OGR-ELM-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },
      { 
        group: "A-OGR-ELM-DUYURU", 
        type: { deny: [27] }, 
        minor: { allow: ['rsc'] }, 
        major: { deny: ['eis'] } 
      },
      { 
        group: "T-OGR-UYE-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },
      { 
        group: "T-OGR-ELM-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },
      { 
        group: "T-OGR-ELM-DUYURU", 
        type: { deny: [27] }, 
        minor: { allow: ['rsc'] }, 
        major: { deny: ['eis'] } 
      },

      # DIGERLERI
      { group: "ARAS-GOR-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "OGR-UYE-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "OGRENCI-DUYURU", type: { allow: [16, 4, 25, 26, 42] }, minor: nil, major: nil },
      { group: "LISANSUSTU-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms', 'phd'] }, major: nil },
      { group: "EMEKLI-DUYURU", type: { allow: [28] }, minor: nil, major: nil },
      { group: "AKADEMIK-EMEKLI-DUYURU", type: { allow: [28] }, minor: { allow: ['aca'] }, major: nil }
    ]

    # Kural Isletme Dongusu
    rules.each do |rule|
      t_allow = rule[:type] ? rule[:type][:allow] : nil
      t_deny  = rule[:type] ? rule[:type][:deny] : nil

      m_allow = rule[:minor] ? rule[:minor][:allow] : nil
      m_deny  = rule[:minor] ? rule[:minor][:deny] : nil

      j_allow = rule[:major] ? rule[:major][:allow] : nil
      j_deny  = rule[:major] ? rule[:major][:deny] : nil

      match_type  = check_match(u_type, t_allow, t_deny)
      match_minor = check_match(u_minor, m_allow, m_deny)
      match_major = check_match(u_major, j_allow, j_deny)

      if match_type && match_minor && match_major
        # Grubu bul veya olustur
        group = Group.find_or_create_by(name: rule[:group])
        
        unless group.users.include?(user)
          group.add(user)
          group.save
          puts ">> [LDAP Group Sync] EKLE: #{user.username} -> #{rule[:group]} grubuna eklendi."
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
  # 3. CONFIG MIDDLEWARE
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
          # Custom field icin gerekli alanlar
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major', 'memberof'],
          mapping: { email: 'uemail' }
        )
      }
  end

  private
   
  # =========================================================
  # 4. AUTH RESULT & EMAIL RECOVERY (FIXED)
  # =========================================================
  def auth_result(auth)
    auth_info = auth.info
    extra_info = auth.extra || {}
    
    # Raw Info'yu guvenli sekilde Hash'e cevir
    raw_info = {}
    if extra_info[:raw_info]
        if extra_info[:raw_info].respond_to?(:to_hash)
            raw_info = extra_info[:raw_info].to_hash
        elsif extra_info[:raw_info].kind_of?(Hash)
            raw_info = extra_info[:raw_info]
        end
    end

    # Email Kurtarma (uemail kontrolu)
    # Net::LDAP Hash yapisinda veriler Array doner! (orn: ["email@metu.edu.tr"])
    if (auth_info[:email].nil? || auth_info[:email].empty?)
      # raw_info key'leri bazen symbol bazen string olabilir, ikisini de dene
      uemail_val = raw_info['uemail'] || raw_info[:uemail]
      
      if uemail_val
        ldap_mail = uemail_val.kind_of?(Array) ? uemail_val.first : uemail_val
        if ldap_mail
            auth_info[:email] = ldap_mail
            puts ">> LDAP: Email 'uemail' alanindan kurtarildi: #{ldap_mail}"
        end
      end
    end
    
    # Kullaniciyi bulma
    result = Auth::Result.new
    if auth.info[:email] && user = User.find_by_email(auth.info[:email])
        result.user = user
    end
    
    # Kullanici hala yoksa standart yontemleri dene
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

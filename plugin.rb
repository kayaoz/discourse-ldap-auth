# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with Rule-Based Group Sync
# version: 2.0.0

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

  def after_authenticate(auth_options)
    # --- DEBUG BASLANGIC ---
    puts "\n=========================================="
    puts "=== LDAP AUTH BASLADI ==="
    
    # 1. Standart islemi calistir
    result = auth_result(auth_options)

    # 2. Kullanici yoksa (ilk giris hatasi vs) islem yapma
    unless result.user
      puts ">> HATA: Kullanici bulunamadigi icin islem yapilamadi."
      return result
    end

    # 3. LDAP Verilerini Al ve Custom Fields Guncelle
    if auth_options.extra && auth_options.extra[:raw_info]
      raw_info = auth_options.extra[:raw_info]
      
      # Helper: Veriyi guvenli okuma
      get_val = ->(key) {
        val = raw_info[key] || raw_info[key.to_s]
        val.respond_to?(:first) ? val.first : val
      }
      
      # Custom Fields Kaydi
      result.user.custom_fields['ldap_type']  = get_val.call(:type).to_s
      result.user.custom_fields['ldap_major'] = get_val.call(:major).to_s
      result.user.custom_fields['ldap_minor'] = get_val.call(:minor).to_s
      
      result.user.save_custom_fields
      puts ">> Custom Fields Guncellendi: Type=#{result.user.custom_fields['ldap_type']}, Major=#{result.user.custom_fields['ldap_major']}"
    end

    # 4. GRUP SENKRONIZASYONU (Sizin Kodunuz)
    sync_groups_based_on_rules(result.user)

    puts "=== LDAP AUTH BITTI ==="
    puts "==========================================\n"

    result
  end

  # --- SIZIN VERDIGINIZ MANTIK BURADA ---
  def sync_groups_based_on_rules(user)
    puts ">> [LDAP Group Sync] Kurallar calistiriliyor..."

    # Kullanici verilerini al
    u_type  = user.custom_fields['ldap_type']
    u_minor = user.custom_fields['ldap_minor']
    u_major = user.custom_fields['ldap_major']

    # KURALLAR LISTESI (Verdiginiz koddan aynen alindi)
    rules = [
      # A-OGRENCI-DUYURU (16 veya 4 veya 25 olsun)
      { group: "A-OGRENCI-DUYURU", type: { allow: [16, 4, 25] }, minor: nil, major: nil },
      
      # LISANS, YUKSEK LISANS, DOKTORA
      { group: "LISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['bs'] }, major: nil },
      { group: "YUKSEKLISANS-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms'] }, major: nil },
      { group: "DOKTORA-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['phd'] }, major: nil },

      # GENEL-DUYURU
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['adm', 'dns'] }, major: { deny: ['eis'] } },
      { group: "GENEL-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },

      # A-OGR-UYE-DUYURU
      { 
        group: "A-OGR-UYE-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },

      # A-OGR-ELM-DUYURU
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

      # T-OGR-UYE-DUYURU
      { 
        group: "T-OGR-UYE-DUYURU", 
        type: { deny: [27, 2, 3, 33] }, 
        minor: { allow: ['aca'] }, 
        major: { deny: ['eis'] } 
      },

      # T-OGR-ELM-DUYURU
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

      # DIGER GRUPLAR
      { group: "ARAS-GOR-DUYURU", type: nil, minor: { allow: ['rsc'] }, major: { deny: ['eis'] } },
      { group: "OGR-UYE-DUYURU", type: nil, minor: { allow: ['aca'] }, major: { deny: ['eis'] } },
      { group: "OGRENCI-DUYURU", type: { allow: [16, 4, 25, 26, 42] }, minor: nil, major: nil },
      { group: "LISANSUSTU-DUYURU", type: { allow: [16, 4, 25] }, minor: { allow: ['ms', 'phd'] }, major: nil },
      { group: "EMEKLI-DUYURU", type: { allow: [28] }, minor: nil, major: nil },
      { group: "AKADEMIK-EMEKLI-DUYURU", type: { allow: [28] }, minor: { allow: ['aca'] }, major: nil }
    ]

    rules.each do |rule|
      t_allow = rule[:type] ? rule[:type][:allow] : nil
      t_deny  = rule[:type] ? rule[:type][:deny] : nil

      m_allow = rule[:minor] ? rule[:minor][:allow] : nil
      m_deny  = rule[:minor] ? rule[:minor][:deny] : nil

      j_allow = rule[:major] ? rule[:major][:allow] : nil
      j_deny  = rule[:major] ? rule[:major][:deny] : nil

      match_type = check_match(u_type, t_allow, t_deny)
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

  # YARDIMCI METOT: Check Match (Verdiginiz kod)
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
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major'],
          mapping: { email: 'uemail' }
        )
      }
  end

  private
   
  def auth_result(auth)
    auth_info = auth.info
    extra_info = auth.extra || {}
    raw_info = extra_info[:raw_info] || {}

    # --- DEBUG: GELEN VERIYI LOGA BAS ---
    puts "\n--------------------------------------------------"
    puts "LDAP DEBUG: auth_result Calisiyor..."
    puts "LDAP DEBUG: Gelen Raw Info Keys: #{raw_info.keys}"
    puts "LDAP DEBUG: Ornek Veri (type): #{raw_info['type'] || raw_info[:type]}"
    puts "LDAP DEBUG: Ornek Veri (memberof): #{raw_info['memberof'] || raw_info[:memberof]}"
    puts "--------------------------------------------------\n"
    # ------------------------------------

    # Email Kurtarma
    if (auth_info[:email].nil? || auth_info[:email].empty?) && raw_info['uemail']
      ldap_mail = raw_info['uemail'].kind_of?(Array) ? raw_info['uemail'].first : raw_info['uemail']
      auth_info[:email] = ldap_mail if ldap_mail
      puts "LDAP DEBUG: Email 'uemail' alanindan kurtarildi: #{ldap_mail}"
    end
    
    # Kullaniciyi bulma
    result = Auth::Result.new
    if auth.info[:email] && user = User.find_by_email(auth.info[:email])
        result.user = user
        puts "LDAP DEBUG: Kullanici email ile bulundu: #{user.username}"
    end
    
    if result.user.nil?
        puts "LDAP DEBUG: Kullanici bulunamadi, yaratma modu: #{SiteSetting.ldap_user_create_mode}"
        case SiteSetting.ldap_user_create_mode
        when 'auto'
            result = LDAPUser.new(auth_info).auth_result
        when 'none'
            ldap_user = LDAPUser.new(auth_info)
            ldap_user.account_exists? ? ldap_user.auth_result : fail_auth('User account does not exist.')
        when 'list'
             fail_auth('List mode not fully implemented.')
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

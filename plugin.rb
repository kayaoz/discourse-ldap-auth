# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication.
# version: 0.8.0
# authors: Jon Bake <jonmbake@gmail.com>

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
    puts "=== LDAP DEBUG: after_authenticate BASLADI ==="
    
    # Gelen ham veriyi gorelim
    if auth_options.extra && auth_options.extra[:raw_info]
      puts ">> LDAP RAW INFO (Ham Veri): #{auth_options.extra[:raw_info].inspect}"
    else
      puts ">> LDAP RAW INFO: BULUNAMADI (Nil)"
    end
    
    puts ">> LDAP INFO (Islemis Veri): #{auth_options.info.inspect}"
    # --- DEBUG ARA ---

    # 1. Standart islemi calistir
    result = auth_result(auth_options)

    puts ">> Standart Islem Sonucu (User): #{result.user ? result.user.username : 'NIL (Bulunamadi)'}"

    # 2. EMAIL ILE KURTARMA YAMASI (User nil ise devreye girer)
    if result.user.nil?
      puts ">> KURTARMA MODU: Kullanici standart yolla gelmedi. Email kontrol ediliyor..."
      
      # LDAP'tan gelen verileri kontrol et
      raw_info = auth_options.extra[:raw_info] if auth_options.extra
      
      # Email adresini farkli alanlardan yakalamaya calis
      ldap_email = auth_options.info[:email] rescue nil
      ldap_email ||= raw_info[:uemail] rescue nil # ODTU ozel alani
      ldap_email ||= raw_info[:mail] rescue nil
      
      # Array gelirse ilkini al (bazen ["email@metu.edu.tr"] doner)
      ldap_email = ldap_email.first if ldap_email.kind_of?(Array)
      
      if ldap_email
        puts ">> KURTARMA MODU: LDAP Email yakalandi: #{ldap_email}"
        puts ">> KURTARMA MODU: Veritabaninda araniyor..."
        
        # Email ile kullaniciyi bul
        if user = User.find_by_email(ldap_email)
          puts ">> KURTARMA BASARILI: Kullanici bulundu: #{user.username} (ID: #{user.id})"
          result.user = user
          
          # Eslestirmeyi veritabanina da yazalim ki bir dahakine ugrasmasin
          # (Opsiyonel ama faydali)
          # UserAssociatedAccount kaydi burada yapilabilir ama su anlik sadece session'a bagliyoruz.
        else
           puts ">> KURTARMA BASARISIZ: Bu email (#{ldap_email}) ile kayitli Discourse kullanicisi YOK."
        end
      else
        puts ">> KURTARMA HATA: Email adresi hicbir yerden okunamadi!"
      end
    end

    # 3. CUSTOM FIELDS KAYDI (Sadece user varsa calisir)
    if result.user && auth_options.extra && auth_options.extra[:raw_info]
      puts ">> CUSTOM FIELDS: Veri isleniyor..."
      raw = auth_options.extra[:raw_info]
      
      # Helper lambda: Hem String ("major") hem Symbol (:major) destekler
      extract_val = ->(key) {
        val = raw[key] || raw[key.to_s]
        # Eger array ise ilkini al
        final_val = val.respond_to?(:first) ? val.first : val
        puts "   -> Veri Okuma [#{key}]: Ham: #{val.inspect} -> Sonuc: #{final_val.inspect}"
        final_val
      }

      # Alanlari guncelle
      if val = extract_val.call(:type)
        result.user.custom_fields['ldap_type'] = val
      end
      
      if val = extract_val.call(:minor)
        result.user.custom_fields['ldap_minor'] = val
      end
      
      if val = extract_val.call(:major)
        result.user.custom_fields['ldap_major'] = val
      end
      
      if result.user.save_custom_fields
        puts ">> CUSTOM FIELDS: Basariyla kaydedildi."
        puts ">> SON DURUM: #{result.user.custom_fields.slice('ldap_type', 'ldap_minor', 'ldap_major')}"
      else
        puts ">> CUSTOM FIELDS HATA: Kayit sirasinda hata olustu."
      end
    else
      puts ">> CUSTOM FIELDS: Atlandi (User yok veya raw_info eksik)"
    end

    puts "=== LDAP DEBUG: after_authenticate BITTI ==="
    puts "==========================================\n"

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
          # In 0.3.0, we fixed a typo in the ldap_bind_dn config name. This fallback will be removed in a future version.
          bind_dn: SiteSetting.ldap_bind_dn.presence || SiteSetting.try(:ldap_bind_db),
          password: SiteSetting.ldap_password,
          filter: SiteSetting.ldap_filter,
          # DEGISIKLIK 2: 'type', 'minor', 'major' alanlarini buraya EKLEDIK.
          attributes: ['uid', 'cn', 'sn', 'mail', 'uemail', 'type', 'minor', 'major'],
          mapping: { email: 'uemail' }
        )
      }
  end

  private
   
  # DEGISIKLIK 3: auth_info artik tum paketi temsil ediyor
  def auth_result(auth)
    # Paketi parcalara ayir
    auth_info = auth.info
    extra_info = auth.extra || {}
    raw_info = extra_info[:raw_info] || {}

    # DEGISIKLIK 4: Manuel Email Kurtarma Operasyonu (Creation oncesi)
    if (auth_info[:email].nil? || auth_info[:email].empty?) && raw_info['uemail']
      Rails.logger.warn("LDAP: Standart email bos. 'uemail' alanindan veri kurtariliyor...")
      
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
        #match on email
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

# frozen_string_literal: true
# name:ldap
# about: A plugin to provide ldap authentication with Background Group Sync, Privacy Lock & Pilot Test Sync (v8.2)
# version: 8.2.0
# authors: Jon Bake <jonmbake@gmail.com>, ODTU Customization

enabled_site_setting :ldap_enabled

# Ruby 3.4.0 Uyumlu Gem Surumleri (500 Hatasi Cozumu)
gem 'net-ldap', '0.19.0'
gem 'pyu-ruby-sasl', '0.0.3.3', require: false
gem 'rubyntlm', '0.3.4', require: false

require 'yaml'
require_relative 'lib/omniauth-ldap/adaptor'
require_relative 'lib/omniauth/strategies/ldap'
require_relative 'lib/ldap_user'

# =============================================================
# 1. ODTU GRUP SENKRONIZASYON MODULU (GİZLİLİK KORUMALI)
# =============================================================
module ::LDAPGroupSync
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

      # --- GIZLILIK AYARI (Sadece Grup Üyeleri ve Yöneticiler Görebilir) ---
      target_visibility = Group.visibility_levels[:members]
      if group.visibility_level != target_visibility
        group.update(
          visibility_level: target_visibility,
          members_visibility_level: target_visibility
        )
      end
      # --------------------------------------------------------------------
      
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
# 2. SIDEKIQ ARKA PLAN GOREVLERI (Performans Icin)
# =============================================================
after_initialize do
  module ::Jobs
    class LdapGroupSync < ::Jobs::Base
      def execute(args)
        user = User.find_by(id: args[:user_id])
        return unless user
        
        ::LDAPGroupSync.sync(user)
      end
    end
  end

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
      
      Jobs.enqueue(:ldap_group_sync, user_id: user.id)
      
      PluginStore.remove('ldap', "pending_#{user.email}")
    end
  end
end

# =============================================================
# 3. AUTHENTICATOR (GIRIS ISLEMI)
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
          attributes: ['uid', 'cn', 'sname', 'fname', 'mail', 'uemail', 'type', 'minor', 'major', 'memberof'],
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
        sname = extract_val.call(:sname)
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
      
      Jobs.enqueue(:ldap_group_sync, user_id: result.user.id)
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

# =============================================================
# 4. SESSİZ TOPLU SENKRONIZASYON (PİLOT TEST VERSİYONU)
# =============================================================
module ::LDAPBulkSync
  def self.run!
    require 'net/ldap'

    puts "==========================================================="
    puts "ODTU LDAP SESSİZ SENKRONİZASYON BAŞLATILIYOR (PİLOT TEST)"
    puts "==========================================================="

    original_email_setting = SiteSetting.disable_emails
    original_welcome_setting = SiteSetting.send_welcome_message
    
    puts "[GÜVENLİK] E-postalar ve Hoş Geldin Özel Mesajları (PM) geçici olarak DURDURULDU."
    SiteSetting.disable_emails = "yes"
    SiteSetting.send_welcome_message = false

    begin
      host = SiteSetting.ldap_hostname
      port = SiteSetting.ldap_port.to_i
      bind_dn = SiteSetting.ldap_bind_dn.presence || SiteSetting.try(:ldap_bind_db)
      password = SiteSetting.ldap_password || ""
      base = SiteSetting.ldap_base

      ldap_args = { host: host, port: port }
      
      if port == 636 || port == 3269
        ldap_args[:encryption] = { method: :simple_tls }
      end

      if bind_dn.present?
        ldap_args[:auth] = { method: :simple, username: bind_dn, password: password }
      end

      ldap = Net::LDAP.new(ldap_args)

      unless ldap.bind
        puts "HATA: LDAP sunucusuna bağlanılamadı! Sebep: #{ldap.get_operation_result.message}"
        return
      end

      # -----------------------------------------------------------------
      # ODTÜ PİLOT TEST LİSTESİ
      # -----------------------------------------------------------------
      test_uids = [
        "leventb", "gdeniz", "euzuner", "ecimen", "bkubra", "keremk",
        "ozdemiri", "rpolat", "ayberk", "erkunt", "aekmekci", "ozsar",
        "mgir", "bakdemir", "hyamuc", "mteker", "ycansiz", "sati",
        "eozkok", "tasker", "adiyaman", "canatali", "tbaykiz", "ozcaglar",
        "erguls", "serkany", "burhanp", "gulserc", "aydiner", "adilga",
        "hdemir", "gokcet", "ftoy", "okosar", "hderin", "altinova",
        "ferman", "etas", "haydar", "cicek", "oelcin", "meleky",
        "eliffile", "elmas", "cihany", "muhsinu", "gubari", "mduman",
        "cengizt", "meral", "murata", "ahmet", "rabiak", "oznurc",
        "sergin", "melekb", "ak", "syayla", "matalay", "yurda",
        "eakman", "ulger", "yaseminy", "ozkocak", "eekoc", "karacan",
        "saba", "yunus"
      ]

      puts "Bağlantı başarılı. Belirtilen #{test_uids.length} kullanıcı sırayla çekiliyor..."

      attrs = ['uid', 'cn', 'fname', 'sname', 'uemail', 'mail', 'type', 'minor', 'major']
      
      created_count = 0
      updated_count = 0

      # Dizideki her bir kullanıcı için sırayla LDAP araması yap
      test_uids.each do |target_uid|
        filter = Net::LDAP::Filter.eq("uid", target_uid)

        ldap.search(base: base, filter: filter, attributes: attrs) do |entry|
          uid = extract_val(entry, :uid)
          email = extract_val(entry, :uemail).presence || extract_val(entry, :mail).presence
          next if email.blank? || uid.blank?

          user = User.find_by_email(email)
          
          if user.nil?
            name = extract_val(entry, :cn).presence || "#{extract_val(entry, :fname)} #{extract_val(entry, :sname)}".strip.presence || uid
            
            begin
              user = User.new(
                email: email,
                username: UserNameSuggester.suggest(uid),
                name: name,
                active: true,
                approved: true,
                trust_level: 1
              )
              user.password = SecureRandom.hex(20)
              user.save!(validate: false)
              
              unless user.email_tokens.exists?(email: email)
                EmailToken.create!(email: email, user_id: user.id, confirmed: true)
              end
              
              created_count += 1
              puts "[YENI] #{email} eklendi."
            rescue => e
              puts "[HATA] #{email} olusturulamadi: #{e.message}"
              next
            end
          else
            updated_count += 1
            puts "[MEVCUT] #{email} bulundu, guncelleniyor."
          end

          user.custom_fields['ldap_type'] = extract_val(entry, :type)
          user.custom_fields['ldap_minor'] = extract_val(entry, :minor)
          user.custom_fields['ldap_major'] = extract_val(entry, :major)
          user.save_custom_fields

          ::LDAPGroupSync.sync(user)
        end
      end

      puts "==========================================================="
      puts "İŞLEM BAŞARIYLA TAMAMLANDI!"
      puts "Yeni Oluşturulan Kullanıcı: #{created_count}"
      puts "Grupları Güncellenen/Kontrol Edilen Kullanıcı: #{updated_count}"
      puts "==========================================================="

    ensure
      SiteSetting.disable_emails = original_email_setting
      SiteSetting.send_welcome_message = original_welcome_setting
      puts "[GÜVENLİK] E-postalar ve Hoş Geldin mesajları tekrar AKTİF edildi."
    end
  end

  def self.extract_val(entry, key)
    val = entry[key]
    val.is_a?(Array) ? val.first.to_s.strip : val.to_s.strip
  end
end

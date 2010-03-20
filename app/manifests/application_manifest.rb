# -*- coding: undecided -*-
require "#{File.dirname(__FILE__)}/../../vendor/plugins/moonshine/lib/moonshine.rb"
class ApplicationManifest < Moonshine::Manifest::Rails
  # The majority of your configuration should be in <tt>config/moonshine.yml</tt>
  # If necessary, you may provide extra configuration directly in this class
  # using the configure method. The hash passed to the configure method is deep
  # merged with what is in <tt>config/moonshine.yml</tt>. This could be used,
  # for example, to store passwords and/or private keys outside of your SCM, or
  # to query a web service for configuration data.
  #
  # In the example below, the value configuration[:custom][:random] can be used in
  # your moonshine settings or templates.
  #
  # require 'net/http'
  # require 'json'
  # random = JSON::load(Net::HTTP.get(URI.parse('http://twitter.com/statuses/public_timeline.json'))).last['id']
  # configure({
  #   :custom => { :random => random  }
  # })

  # The default_stack recipe install Rails, Apache, Passenger, the database from
  # database.yml, Postfix, Cron, logrotate and NTP. See lib/moonshine/manifest/rails.rb
  # for details. To customize, remove this recipe and specify the components you want.
  #  recipe :default_stack

  # Needed for postgres's UTF8 configuration
  #    FATAL:  invalid value for parameter "lc_messages": "en_US.UTF-8"
  def locale_gen
    exec("locale-gen", {
           :command => "/usr/sbin/locale-gen en_US.UTF-8"
         })
  end

  # Override the default one with a recipe that doesn't use db:migrate
  def rails_bootstrap
    rake 'moonshine:bootstrap',
      :alias => 'rails_bootstrap',
      :refreshonly => true
  end

  
  # edavis10: hardcoded, missing config/database.yml
  # Removed because they are not needed :rails_migrations, :rails_logrotate
  def mysql_stack
    recipe :apache_server
    recipe :passenger_gem, :passenger_configure_gem_path, :passenger_apache_module, :passenger_site
    recipe :mysql_server, :mysql_gem, :mysql_fixup_debian_start
    #recipe :mysql_database, :mysql_user # TODO: parses database.yml
    recipe :rails_rake_environment, :rails_gems, :rails_directories, :rails_bootstrap
    recipe :ntp, :time_zone, :postfix, :cron_packages, :motd, :security_updates
  end
#  recipe :mysql_stack

  def postgres_stack
    recipe :locale_gen
    recipe :apache_server
    recipe :passenger_gem, :passenger_configure_gem_path, :passenger_apache_module, :passenger_site
    recipe :postgresql_server, :postgresql_gem
    #recipe :postgresql_user, :postgresql_database # TODO: parses database.yml
    recipe :rails_rake_environment, :rails_gems, :rails_directories, :rails_bootstrap
    recipe :ntp, :time_zone, :postfix, :cron_packages, :motd, :security_updates

  end
  #  recipe :postgres_stack

  def sqlite_stack
    recipe :apache_server
    recipe :passenger_gem, :passenger_configure_gem_path, :passenger_apache_module, :passenger_site
    self.class.recipe :sqlite3
    recipe :rails_rake_environment, :rails_gems, :rails_directories, :rails_bootstrap
    recipe :ntp, :time_zone, :postfix, :cron_packages, :motd, :security_updates
  end
  recipe :sqlite_stack

  configure(

            :ssh => { :port => 22222, :allow_users => ['rails'] },
            :iptables => { :rules => [

                                      # Set default-deny policies for all three default chains
                                      '-P INPUT DROP',
                                      '-P FORWARD DROP',
                                      '-P OUTPUT DROP',

                                      # Give free reign to the loopback interfaces, i.e. local processes may connect
                                      # to other processes' listening-ports.
                                      '-A INPUT  -i lo -j ACCEPT',
                                      '-A OUTPUT -o lo -j ACCEPT',
                                      
                                      # Do some rudimentary anti-IP-spoofing drops. The rule of thumb is "drop
                                      #  any source IP address which is impossible" (per RFC 1918)
                                      #
                                      '-A INPUT -s 255.0.0.0/8 -j DROP',
                                      '-A INPUT -s 0.0.0.0/8 -j DROP',
                                      '-A INPUT -s 127.0.0.0/8 -j DROP',
                                      '-A INPUT -s 192.168.0.0/16 -j DROP',
                                      '-A INPUT -s 172.16.0.0/12 -j DROP',
                                      '-A INPUT -s 10.0.0.0/8 -j DROP',
                                      
                                      # The following will NOT interfere with local inter-process traffic, whose
                                      #   packets have the source IP of the local loopback interface, e.g. 127.0.0.1

                                      # TODO: need to get the local ip
#                                      '-A INPUT -s $IP_LOCAL -j DROP',

                                      # Tell netfilter that all TCP sessions do indeed begin with SYN
                                      #   (There may be some RFC-non-compliant application somewhere which 
                                      #    begins its transactions otherwise, but if so I've never heard of it)
                                      
                                      '-A INPUT -p tcp ! --syn -m state --state NEW -j DROP',
                                      
                                      # Finally, the meat of our packet-filtering policy:
                                      
                                      # INBOUND POLICY
                                      #   (Applies to packets entering our network interface from the network, 
                                      #   and addressed to this host)
                                      
                                      # Accept inbound packets that are part of previously-OK'ed sessions
                                      '-A INPUT -j ACCEPT -m state --state ESTABLISHED,RELATED',
                                      
                                      # Accept inbound packets which initiate SSH sessions on 22222
                                      '-A INPUT -p tcp -j ACCEPT --dport 22222 -m state --state NEW',
                                      
                                      # Accept inbound packets which initiate HTTP sessions
                                      '-A INPUT -p tcp -j ACCEPT --dport 80 -m state --state NEW',
                                      '-A INPUT -p tcp -j ACCEPT --dport 81 -m state --state NEW',

                                      # Accept inbound packets which initiate HTTPS sessions
                                      '-A INPUT -p tcp -j ACCEPT --dport 443 -m state --state NEW',

                                      # ping
                                      '-A INPUT -p icmp -j ACCEPT --icmp-type echo-request',
                                      
                                      # Log and drop anything not accepted above
                                      #   (Obviously we want to log any packet that doesn't match any ACCEPT rule, for
                                      #    both security and troubleshooting. Note that the final "DROP" rule is 
                                      #    redundant if the default policy is already DROP, but redundant security is
                                      #    usually a good thing.)
                                      #
                                      '-A INPUT -j DROP',
                                      
                                      # OUTBOUND POLICY
                                      #   (Applies to packets sent to the network interface (NOT loopback)
                                      #   from local processes)
                                      
                                      # If it's part of an approved connection, let it out
                                      '-I OUTPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT',
                                      
                                      # Allow outbound ping 
                                      #   (For testing only! If someone compromises your system they may attempt
                                      #    to use ping to identify other active IP addresses on the DMZ. Comment
                                      #    this rule out when you don't need to use it yourself!)

                                      '-A OUTPUT -p icmp -j ACCEPT --icmp-type echo-request',
                                      
                                      # Allow outbound DNS queries, e.g. to resolve IPs in logs
                                      #   (Many network applications break or radically slow down if they
                                      #   can't use DNS. Although DNS queries usually use UDP 53, they may also use TCP 
                                      #   53. Although TCP 53 is normally used for zone-transfers, DNS queries with 
                                      #   replies greater than 512 bytes also use TCP 53, so we'll allow both TCP and UDP 
                                      #   53 here
                                      # 
                                      '-A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT',
                                      '-A OUTPUT -p tcp --dport 53 -m state --state NEW -j ACCEPT',

                                      # Allow outbound HTTP, HTTPS.  Needed to fetch packages and just general use
                                      #
                                      '-A OUTPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT',
                                      '-A OUTPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT',
                                      # Allow outbound SMTP.
                                      #
                                      '-A OUTPUT -p tcp --dport 25 -m state --state NEW -j ACCEPT',
                                      
                                      # Allow outbound NTP.
                                      #
                                      '-A OUTPUT -p udp --dport 123 -m state --state NEW -j ACCEPT',

                                      # Allow outboung SSH
                                      #
                                      '-A OUTPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT',

                                      # Allow outboung IRC
                                      #
                                      '-A OUTPUT -p tcp --dport 6667 -m state --state NEW -j ACCEPT',

                                      # Allow outbound IMAP
                                      '-A OUTPUT -p tcp --dport 143 -m state --state NEW -j ACCEPT',

                                      # Log & drop anything not accepted above; if for no other reason, for troubleshooting
                                      #
                                      # NOTE: you might consider setting your log-checker (e.g. Swatch) to
                                      #   sound an alarm whenever this rule fires; unexpected outbound trans-
                                      #   actions are often a sign of intruders!
                                      #
                                      '-A OUTPUT -j ACCEPT',
                                      
                                      # Log & drop ALL incoming packets destined anywhere but here.
                                      #   (We already set the default FORWARD policy to DROP. But this is 
                                      #   yet another free, reassuring redundancy, so why not throw it in?)
                                      #
                                      '-A FORWARD -j DROP'
                                     ]})
  
  plugin :iptables
  recipe :iptables
  recipe :ssh


  # Add your application's custom requirements here
  def application_packages
    # If you've already told Moonshine about a package required by a gem with
    # :apt_gems in <tt>moonshine.yml</tt> you do not need to include it here.
    # package 'some_native_package', :ensure => :installed

    # some_rake_task = "/usr/bin/rake -f #{configuration[:deploy_to]}/current/Rakefile custom:task RAILS_ENV=#{ENV['RAILS_ENV']}"
    # cron 'custom:task', :command => some_rake_task, :user => configuration[:user], :minute => 0, :hour => 0

    # %w( root rails ).each do |user|
    #   mailalias user, :recipient => 'you@domain.com'
    # end

    # farm_config = <<-CONFIG
    #   MOOCOWS = 3
    #   HORSIES = 10
    # CONFIG
    # file '/etc/farm.conf', :ensure => :present, :content => farm_config

    # Logs for Rails, MySQL, and Apache are rotated by default
    # logrotate '/var/log/some_service.log', :options => %w(weekly missingok compress), :postrotate => '/etc/init.d/some_service restart'

    # Only run the following on the 'testing' stage using capistrano-ext's multistage functionality.
    # on_stage 'testing' do
    #   file '/etc/motd', :ensure => :file, :content => "Welcome to the TEST server!"
    # end
  end
  # The following line includes the 'application_packages' recipe defined above
  recipe :application_packages
end

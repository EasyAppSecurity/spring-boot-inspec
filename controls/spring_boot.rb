# encoding: utf-8
# frozen_string_literal: true

#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

title 'Spring Boot Secure Configuration'

require 'zip'

spring_boot_executable = attribute(
  'spring_boot_executable',
  default: '/opt/springbootapp/springbootapp.jar',
  description: 'The path on the system where Spring Boot application .jar file is located'
)

spring_boot_service = attribute(
  'spring_boot_service',
  default: 'springbootapp',
  description: 'The name of Spring Boot application service'
)

spring_boot_service_path = attribute(
  'spring_boot_service_path',
  default: '/etc/systemd/system/springbootapp.service',
  description: 'The path on the system where Spring Boot application configuration file is located'
)

spring_boot_user = attribute(
  'spring_boot_user',
  default: 'springbootappuser',
  description: 'The system user account that Spring Boot application service runs as'
)

spring_boot_config = attribute(
  'spring_boot_config',
  description: 'Path to Spring Boot application configuration file. In case if configuration file is inside the jar file, specify the path in the following format - /path/to/springbootapp.jar!/resources/application.properties',
  default: '/opt/springbootapp/springbootapp.jar!/application-default.properties'
)

spring_boot_log_path = attribute(
  'spring_boot_log_path',
  description: 'Path to Spring Boot logging file (.log) or directory',
  default: '/etc/springbootapp/application.log'
)

options = {
  assignment_regex: /^\s*([^=]*?)\s*=\s*(.*?)\s*$/,
  multiple_values: false
}

spring_boot_parsed_config = ''

control 'spring-boot-1.1' do
  impact 1.0
  title 'Verify Spring Boot configuration permissions are set to 640 or more restrictive (if not inside .jar file)'
  desc 'Verify Spring Boot configuration permissions are set to 640 or more restrictive (if not inside .jar file)'
  
	if spring_boot_config.to_s.include? "!"
		pathes_arr = spring_boot_config.to_s.split('!')

		if File.exist?(pathes_arr[0])
			if pathes_arr.length() > 1
				entry_for_search = pathes_arr[1].dup.delete_prefix("/")
				Zip::InputStream.open(pathes_arr[0]) do |zis|
				  while (entry = zis.get_next_entry)
					if entry.name == entry_for_search
						if entry.file?
							spring_boot_parsed_config = entry.get_input_stream.read
						end
						break
					end
				  end
				end
			end
		end
	else
	  only_if do
		file(spring_boot_config.to_s).exist?
	  end

	  describe file(spring_boot_config) do
		it { should be_file }
		its('owner') { should eq spring_boot_user }
		it { should_not be_writable.by('owner') }
		it { should_not be_writable.by('group') }
		it { should_not be_executable.by('group') }
		it { should_not be_readable.by('others') }
		it { should_not be_writable.by('others') }
		it { should_not be_executable }
	  end
	  
	  spring_boot_parsed_config = File.read(spring_boot_config.to_s)
	end
end

control 'spring-boot-1.2' do
  impact 1.0
  title 'Ensure that Spring boot application service is running'
  desc 'Ensure that Spring boot application is running and enabled'
  
  describe service(spring_boot_service) do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'spring-boot-1.3' do
  impact 1.0
  title 'Ensure Spring boot application is not running as root'
  desc 'Ensure Spring boot application is not running as root'
  
  only_if do
    command('java').exist?
  end

  describe processes('java') do
    its('users') { should_not eq ['root'] }
  end
end

control 'spring-boot-1.4' do
  impact 1.0
  title 'Verify that Spring boot application service file permissions are set to 644 or more restrictive'
  desc 'Verify that Spring boot application service file permissions are correctly set to \'644\' or more restrictive.'
  
  only_if do
    file(spring_boot_service_path.to_s).exist?
  end

  describe file(spring_boot_service_path) do
    it { should exist }
    it { should be_file }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should be_readable.by('group') }
    it { should_not be_writable.by('group') }
    it { should be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'spring-boot-1.5' do
  impact 1.0
  title 'Verify access to Spring boot log files'
  desc 'Verify access to Spring boot log files'
  
  only_if do
    directory(spring_boot_log_path.to_s).exist?
  end

  describe directory(spring_boot_log_path) do
    it { should exist }
    it { should be_readable.by('owner') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_readable.by('other') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable }
  end
end

control 'spring-boot-1.6' do
  impact 1.0
  title 'Verify Spring Boot SSL settings'
  desc 'Verify Spring Boot SSL settings'
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.ciphers'] do
   it { should_not be_nil }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.enabled'] do
   it { should_not eq 'false' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.protocol'] do
   it { should eq 'TLS' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.key-store'] do
   it { should_not be_nil }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.enabled-protocols'] do
   it { should eq 'TLSv1.2' }
  end
  
end

control 'spring-boot-1.7' do
  impact 1.0
  title 'Verify Integration with HashiCorp Vault is enabled'
  desc 'Verify Integration with HashiCorp Vault is enabled'
  
  describe parse_config(spring_boot_parsed_config, options).params['spring.vault.uri'] do
   it { should_not be_nil }
  end
   
end

control 'spring-boot-1.8' do
  impact 0.5
  title 'Ensure database queries are not included binding parameters'
  desc 'Ensure database queries are not included binding parameters'
  
  describe parse_config(spring_boot_parsed_config, options).params['logging.level.org.hibernate.type.descriptor.sql'] do
   it { should be_nil }
  end
   
end

control 'spring-boot-1.9' do
  impact 1.0
  title 'Ensure HTTP without TLS is not used for all the integrations'
  desc 'Ensure HTTP without TLS is not used for all the integrations'
  
  describe command('echo #{spring_boot_parsed_config} | grep http://'), :sensitive do
    its(:stdout) { should be_empty }
  end
   
end

control 'spring-boot-2.0' do
  impact 1.0
  title 'Ensure superuser account is not used for the database integration'
  desc 'Ensure superuser account is not used for the database integration'
  
  if spring_boot_parsed_config.to_s.downcase.include? "postgres"
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
		it { should_not match(/user\s*=\s*(postgres)/) }
	end
	
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.username'] do
		it { should_not eq 'postgres' }
	end
  end
  
  if spring_boot_parsed_config.to_s.downcase.include? "sqlserver"
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
		it { should_not match(/user\s*=\s*(sa)/) }
	end
	
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.username'] do
		it { should_not eq 'sa' }
	end
  end
     
end

control 'spring-boot-2.1' do
  impact 1.0
  title 'Ensure TLS is used for the database integration'
  desc 'Ensure TLS is used for the database integration'
  
  if spring_boot_parsed_config.to_s.downcase.include? "postgres"
	describe.one do
		describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
			it { should match(/sslmode\s*=\s*(verify-ca|verify-full|require)/) }
		end
		
		describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
			it { should match(/ssl\s*=\s*(true)/) }
		end
	end
  end
  
  if spring_boot_parsed_config.to_s.downcase.include? "sqlserver"
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
		it { should match(/encrypt\s*=\s*(true)/) }
	end
	
	describe parse_config(spring_boot_parsed_config, options).params['spring.datasource.url'] do
		it { should_not match(/trustServerCertificate\s*=\s*(true)/) }
	end
  end
     
end

control 'spring-boot-2.2' do
  impact 1.0
  title 'Ensure TLS and authentication is used for SMTP'
  desc 'Ensure TLS is used for SMTP'
  
  if spring_boot_parsed_config.to_s.downcase.include? "spring.mail.host"
	  spring_mail_security_properties = ['spring.mail.properties.mail.smtp.auth', 
	  'spring.mail.properties.mail.smtp.starttls.enable', 'spring.mail.properties.mail.smtp.starttls.required']
	  
	  spring_mail_security_properties.each do |spring_mail_security_property|
		describe parse_config(spring_boot_parsed_config, options).params["#{spring_mail_security_property}"] do
			it { should eq 'true' }
		end
	  end

  end
end

control 'spring-boot-2.3' do
  impact 1.0
  title 'Ensure Spring Boot actuator API is protected'
  desc 'Ensure Spring Boot actuator API is protected'
  
  management_server_alone = true
  
  server_port = parse_config(spring_boot_parsed_config, options).params['management.server.port']
  if server_port == nil
	server_port = parse_config(spring_boot_parsed_config, options).params['management.port']
  end
  if server_port == nil
	server_port = parse_config(spring_boot_parsed_config, options).params['server.port']
	management_server_alone = false
  end
  if server_port == nil
	server_port = '8080'
  end
  
  actuator_base_path = parse_config(spring_boot_parsed_config, options).params['management.endpoints.web.base-path']
  if actuator_base_path == nil
	actuator_base_path = parse_config(spring_boot_parsed_config, options).params['management.context-path']
  end
  if actuator_base_path == nil
	actuator_base_path = '/actuator'
  end
  
  if !management_server_alone
	context_path = parse_config(spring_boot_parsed_config, options).params['server.contextPath']
	if context_path != nil
		actuator_base_path = context_path + actuator_base_path
	end
  end
  
  protocol = 'http'
  if spring_boot_parsed_config.to_s.downcase.include? "management.server.ssl." && management_server_alone
	management_ssl_enabled_option = parse_config(spring_boot_parsed_config, options).params['management.server.ssl.enabled']
	if management_ssl_enabled_option != false
		protocol = 'https'
	end
  end
  
  if spring_boot_parsed_config.to_s.downcase.include? "server.ssl." && !management_server_alone
	ssl_enabled_option = parse_config(spring_boot_parsed_config, options).params['server.ssl.enabled']
	if ssl_enabled_option != false
		protocol = 'https'
	end
  end
  
  interfaces = command("hostname -I").stdout.strip.split(" ")
  
  endpoints = ['auditevents', 'beans', 'caches', 'conditions', 'configprops', 
	'env', 'flyway', 'health', 'heapdump', 'httptrace', 'info', 'integrationgraph',
	'jolokia', 'logfile', 'loggers', 'liquibase', 'metrics', 'mappings', 'prometheus',
	'scheduledtasks', 'sessions', 'shutdown', 'threaddump']

  interfaces.each do |interface|
	endpoints.each do |endpoint|
		endpoint_path = protocol + '://' + interface + ":" + server_port + actuator_base_path + "/" + endpoint
		describe http(endpoint_path, ssl_verify: false) do
			its("status") { should_not cmp 200 }
		end
	end
  end
  
end

control 'spring-boot-2.4' do
  impact 1.0
  title 'Ensure Spring Boot actuator endpoints are not enabled'
  desc 'Ensure Spring Boot actuator endpoints not enabled'
  
  endpoints_properties = ['loggers.enabled', 'auditevents.enabled', 'autoconfig.enabled', 'beans.enabled',
  'configprops.enabled', 'heapdump.enabled', 'dump.enabled', 'env.enabled', 'error.enabled', 'info.enabled',
  'metrics.enabled', 'mappings.enabled', 'shutdown.enabled', 'trace.enabled']
  
  endpoints_props_prefixes = ['endpoints.', 'management.endpoint.']
  
  endpoints_props_prefixes.each do |endpoints_props_prefix|
      endpoints_properties.each do |endpoints_property|
		  full_property_path = endpoints_props_prefix + endpoints_property
		  describe parse_config(spring_boot_parsed_config, options).params["#{full_property_path}"] do
			it { should_not eq 'true' }
		  end
	  end
  end
  
  not_whilecard_endpoints_properties = ['management.endpoints.jmx.exposure.include', 
  'management.endpoints.web.exposure.include', 'management.endpoints.web.cors.allow-credentials']
  
  not_whilecard_endpoints_properties.each do |not_whilecard_endpoints_property|
	  describe parse_config(spring_boot_parsed_config, options).params["#{not_whilecard_endpoints_property}"] do
		it { should_not eq '*' }
	  end
  end
  
end

control 'spring-boot-2.5' do
  impact 0.5
  title 'Ensure debus logs are not enabled in production'
  desc 'Ensure debus logs are not enabled in production'
  
  describe parse_config(spring_boot_parsed_config, options) do
	its("debug") { should_not eq 'true' }
	its("trace") { should_not eq 'true' }
  end
end

control 'spring-boot-2.6' do
  impact 0.5
  title 'Ensure admin features and management beans are not enabled in production if possible'
  desc 'Ensure admin features and management beans are not enabled in production if possible'
  
  describe parse_config(spring_boot_parsed_config, options).params["spring.application.admin.enabled"] do
	it { should_not eq 'true' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params["spring.jmx.enabled"] do
	it { should_not eq 'true' }
  end
end

control 'spring-boot-2.7' do
  impact 0.5
  title 'Ensure stracktrace is not included on error pages'
  desc 'Ensure stracktrace is not included on error pages'
  
  if spring_boot_parsed_config.to_s.include? "server.error.include-stacktrace"
	  describe parse_config(spring_boot_parsed_config, options).params["server.error.include-stacktrace"] do
		it { should eq 'never' }
	  end
  end
  
end

control 'spring-boot-2.8' do
  impact 1.0
  title 'Ensure Cookies security attributes are set'
  desc 'Ensure Cookies security attributes are set'
  
  describe parse_config(spring_boot_parsed_config, options).params["server.servlet.session.cookie.http-only"] do
	it { should eq 'true' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params["server.servlet.session.cookie.secure"] do
	it { should eq 'true' }
  end
  
end

control 'spring-boot-2.9' do
  impact 0.5
  title 'Validate TLS is used for LDAP connection'
  desc 'Validate TLS is used for LDAP connection'
  
  if spring_boot_parsed_config.to_s.include? "spring.ldap."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.ldap.urls"] do
		it { should_not include 'ldap://' }
	  end
  end
  
end

control 'spring-boot-3.0' do
  impact 1.0
  title 'Ensure Spring Boot default user is not used'
  desc 'Ensure Spring Boot default user is not used'
  
  describe parse_config(spring_boot_parsed_config, options).params["spring.security.user.name"] do
	it { should be_nil }
  end
  
end

control 'spring-boot-3.1' do
  impact 1.0
  title 'Ensure TLS is used for COUCHBASE (if used)'
  desc 'Ensure TLS is used for COUCHBASE (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.couchbase."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.couchbase.env.ssl.key-store"] do
		it { should_not be_nil }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.couchbase.env.ssl.enabled"] do
		it { should_not eq 'false' }
	  end
  end
  
end

control 'spring-boot-3.1' do
  impact 1.0
  title 'Ensure TLS is used for CASSANDRA (if used)'
  desc 'Ensure TLS is used for CASSANDRA (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.data.cassandra."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.data.cassandra.ssl"] do
		it { should_not eq 'false' }
	  end
  end
  
end

control 'spring-boot-3.2' do
  impact 1.0
  title 'Ensure no default username or password is used for CASSANDRA integration (if used)'
  desc 'Ensure no default username or password is used for CASSANDRA integration (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.data.cassandra."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.data.cassandra.username"] do
		it { should_not eq 'cassandra' }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.data.cassandra.password"], :sensitive do
		it { should_not eq 'cassandra' }
	  end
  end
  
end

control 'spring-boot-3.3' do
  impact 1.0
  title 'Ensure MongoDB is accessed with authentication (if used)'
  desc 'Ensure MongoDB is accessed with authentication (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.data.mongodb.host"
	  describe parse_config(spring_boot_parsed_config, options).params["spring.data.mongodb.username"] do
		it { should_not be_nil }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.data.mongodb.password"], :sensitive do
		it { should_not be_nil }
	  end
  end
  
end

control 'spring-boot-3.4' do
  impact 1.0
  title 'Ensure InfluxDB is accessed with authentication (if used)'
  desc 'Ensure InfluxDB is accessed with authentication (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.influx.url"
	  describe parse_config(spring_boot_parsed_config, options).params["spring.influx.user"] do
		it { should_not be_nil }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.influx.password"], :sensitive do
		it { should_not be_nil }
	  end
  end
  
end

control 'spring-boot-3.4' do
  impact 1.0
  title 'Ensure Redis is accessed with authentication (if used)'
  desc 'Ensure Redis is accessed with authentication (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.redis.host"
	  describe parse_config(spring_boot_parsed_config, options).params["spring.redis.password"], :sensitive do
		it { should_not be_nil }
	  end
  end
  
end

control 'spring-boot-3.5' do
  impact 1.0
  title 'Ensure TLS is used for Redis (if used)'
  desc 'Ensure TLS is used for Redis (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.redis."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.redis.ssl"] do
		it { should eq 'true' }
	  end
  end
  
end

control 'spring-boot-3.6' do
  impact 1.0
  title 'Ensure TLS is used for ActiveMQ (if used)'
  desc 'Ensure TLS is used for ActiveMQ (if used)'
  
  if spring_boot_parsed_config.to_s.include? "spring.activemq."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.activemq.broker-url"] do
		it { should include 'ssl://' }
	  end
  end
  
end

control 'spring-boot-3.7' do
  impact 1.0
  title 'Ensure no default credentials for ActiveMQ are used'
  desc 'Ensure no default credentials for ActiveMQ are used'
  
  if spring_boot_parsed_config.to_s.include? "spring.activemq."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.activemq.user"] do
		it { should_not eq 'admin' }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.activemq.password"], :sensitive do
		it { should_not eq 'admin' }
	  end
  end
  
end

control 'spring-boot-3.8' do
  impact 1.0
  title 'Ensure TLS is used for Kafka'
  desc 'Ensure TLS is used for Kafka'
  
  if spring_boot_parsed_config.to_s.include? "spring.kafka.admin."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.admin.ssl.keystore-location"] do
		it { should_not be_nil }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.admin.ssl.protocol"] do
		it { should eq 'TLS' }
	  end
  end
  
  if spring_boot_parsed_config.to_s.include? "spring.kafka.consumer."
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.consumer.ssl.keystore-location"] do
		it { should_not be_nil }
	 end
	  
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.consumer.ssl.protocol"] do
		it { should eq 'TLS' }
	 end
  end
  
  if spring_boot_parsed_config.to_s.include? "spring.kafka.producer."
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.producer.ssl.keystore-location"] do
		it { should_not be_nil }
	 end
	  
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.producer.ssl.protocol"] do
		it { should eq 'TLS' }
	 end
  end
  
  if spring_boot_parsed_config.to_s.include? "spring.kafka."
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.ssl.keystore-location"] do
		it { should_not be_nil }
	 end
	  
	 describe parse_config(spring_boot_parsed_config, options).params["spring.kafka.ssl.protocol"] do
		it { should eq 'TLS' }
	 end
  end
  
end

control 'spring-boot-3.9' do
  impact 1.0
  title 'Ensure no default credentials for RabbitMQ are used'
  desc 'Ensure no default credentials for RabbitMQ are used'
  
  if spring_boot_parsed_config.to_s.include? "spring.rabbitmq."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.rabbitmq.username"] do
		it { should_not eq 'guest' }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.rabbitmq.password"], :sensitive do
		it { should_not eq 'guest' }
	  end
  end
  
end

control 'spring-boot-3.9' do
  impact 1.0
  title 'Ensure TLS for RabbitMQ is used'
  desc 'Ensure TLS for RabbitMQ is used'
  
  if spring_boot_parsed_config.to_s.include? "spring.rabbitmq."
	  describe parse_config(spring_boot_parsed_config, options).params["spring.rabbitmq.ssl.key-store"] do
		it { should_not be_nil }
	  end
	  
	  describe parse_config(spring_boot_parsed_config, options).params["spring.rabbitmq.ssl.enabled"] do
		it { should eq 'true' }
	  end
  end
  
end

control 'spring-boot-4.0' do
  impact 0.5
  title 'Ensure TLS validation is not skipped for Cloud Foundry actuator endpoints'
  desc 'Ensure TLS validation is not skipped for Cloud Foundry actuator endpoints'
  
  if spring_boot_parsed_config.to_s.include? "management.cloudfoundry."
	  describe parse_config(spring_boot_parsed_config, options).params["management.cloudfoundry.skip-ssl-validation"] do
		it { should_not eq 'true' }
	  end
  end
  
end

control 'spring-boot-4.0' do
  impact 0.5
  title 'Ensure all the management endpoints are disabled by default'
  desc 'Ensure all the management endpoints are disabled by default'
  
  if spring_boot_parsed_config.to_s.include? "management.endpoints."
	  describe parse_config(spring_boot_parsed_config, options).params["management.endpoints.enabled-by-default"] do
		it { should eq 'false' }
	  end
  end
  
end

control 'spring-boot-4.1' do
  impact 1.0
  title 'Ensure cookies are not included in the trace (if used)'
  desc 'Ensure cookies are not included in the trace (if used)'
  
  if spring_boot_parsed_config.to_s.include? "management.trace."
	  http_trace_enabled_option = parse_config(spring_boot_parsed_config, options).params["management.trace.http.enabled"]
	  if http_trace_enabled_option == 'true'
		  describe parse_config(spring_boot_parsed_config, options).params["management.trace.http.include"] do
			it { should_not include 'cookies' }
		  end
	  end
  end
  
end

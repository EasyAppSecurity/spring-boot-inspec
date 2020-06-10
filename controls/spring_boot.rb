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
   it { should eq 'true' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.protocol'] do
   it { should eq 'TLS' }
  end
  
  describe parse_config(spring_boot_parsed_config, options).params['server.ssl.key-store'] do
   it { should_not be_nil }
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
	  describe parse_config(spring_boot_parsed_config, options).params['spring.mail.properties.mail.smtp.auth'] do
	   it { should eq 'true' }
	  end
  
	  describe parse_config(spring_boot_parsed_config, options).params['spring.mail.properties.mail.smtp.starttls.enable'] do
	   it { should eq 'true' }
	  end
  
	  describe parse_config(spring_boot_parsed_config, options).params['spring.mail.properties.mail.smtp.starttls.required'] do
	   it { should eq 'true' }
	  end
  end
end


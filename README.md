Spring Boot application Security Assessment InSpec profile

## Standalone Usage

1. Install [InSpec](https://github.com/chef/inspec) for the profile execution

2. Clone the repository
```bash
$ git clone https://github.com/EasyAppSecurity/spring-boot-inspec

```
3. Create properties .yml file in **inspec-vault/attributes** folder, where specify Vault settings. 
For example, vault-centos7-test.yml:
```yaml
spring_boot_executable : /home/osboxes/example.jar # The path on the system where Spring Boot application .jar file is located
spring_boot_service : example-app-service # The name of Spring Boot application service
spring_boot_service_path : /etc/systemd/system/example_app.service # The path on the system where Spring Boot application configuration file is located
spring_boot_user : example_app_user # The system user account that Spring Boot application service runs as
spring_boot_config : /home/osboxes/example.jar!/application-default.properties # Path to Spring Boot application configuration file. In case if configuration file is inside the jar file, specify the path in the following format - /path/to/springbootapp.jar!/resources/application.properties
spring_boot_log_path : /var/log/example_logs # Path to Spring Boot logging file (.log) or directory

```
4. Execute the profile:
```bash
$ inspec exec spring-boot-inspec --input-file spring-boot-inspec/attributes/spring-boot-centos7-test.yml --reporter html:/tmp/inspec-spring-boot.html

``` 
		
## License and Author

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

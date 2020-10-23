# Crowdstrike Queries
### Description

##### A list of queries that I used to perform basic forensic activities
------------------------
| Query        | Description           | Scope  |
| ------------- |:-------------:| -----:|
|event_simpleName=DnsRequest \| <br /> rex field=DomainName "[@\.](?<domain>\w+\.\w+)$"\| <br /> stats count(domain) AS "Amount" by domain\|<br />  rename domain AS "Top Level Domain"\| <br /> sort - Amount|<br /> Count all top domain access|Network|
| event_simpleName=DnsRequest \| <br />rex field=DomainName "[@\.](?<domain>\w+\.\w+)$"\| <br />top limit=100 domain | List top 100 domain contacted by our users Usefull to detect a Mining |Network|
|event_simpleName=DnsRequest \| <br />rex field=DomainName "[@\.](?<domain>\w+\.\w+)$"\| <br />rare limit=100 domain|List "rare" 100 domain contacted by our users Usefull to detect unusual DN|Network|
|event_simpleName=DnsRequest earliest=-1h@h latest=@h<br />\|regex DomainName!="google\.com\|microsoft\.com\|zoom\.com\|office\.com\|<br />windows\.com\|apple\.com\|icloud\.net\|<br />facebook\.com\|1password\.com\|github\.io\|skype\.com\|google\.co\.jp<br />\|PC*" <br />\|stats values(ComputerName) count by DomainName <br />\|where count < 2<br />\|rare limit=50 DomainName|Show me a list of domain name requested less than 2 times during the last hour|Network|
|event_simpleName="NewExecutableRenamed" earliest=-1h@h latest=@h<br />\|rename TargetFileName as ImageFileName<br />\|join ImageFileName <br />\[ search event_simpleName="ProcessRollup2" ]<br />\|table ComputerName SourceFileName ImageFileName CommandLine|Executable name changed the last hour|Cross platform|
|index = main <br />\| dedup ComputerName<br />\| table ComputerName aid aip MAC event_platform|Quick overview about the endpoint information <br />aid (agent id) is really critical to perform investigation|Cross platform|
|event_simpleName=CriticalFileAccessed<br />\| stats values(TargetFileName) as Target_File_Name, count by ComputerName , event_platform<br />\| search count > 10<br />\| table event_platform ComputerName Target_File_Name count |Count the amount of Critical file accessed and display the platform, Computer Name , the Targeted File Name , and count|Mac/Linux|

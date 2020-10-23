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
|event_simpleName=CriticalFileAccessed<br />\| table event_platform ComputerName FileName TargetFileName|Critical file accessed|Mac/Linux|
|event_simpleName=ProcessRollup2 (FileName=net.exe OR FileName=ipconfig.exe OR FileName=whoami.exe OR FileName=quser.exe OR FileName=ping.exe OR FileName=netstat.exe OR FileName=tasklist.exe OR FileName=Hostname.exe OR FileName=at.exe) | table ComputerName FileName CommandLine|Reconnaissance Tools installed|Windows|
|event_simpleName=*ProcessRollup2 event_platform=Mac chmod<br />\|table ComputerName CommandLine|see chmod performed|Mac/Linux|
|event_simpleName=*ProcessRollup2 event_platform=Mac chown<br />\|table ComputerName CommandLine|see chown performed|Mac/Linux|
|event_platform=Mac event_simpleName=ProcessRollup2 (CommandLine="/tmp/*" OR CommandLine="/private/tmp/*")<br />\|stats values(ComputerName) count by CommandLine |Commandline executed with /tmp/ or /private/tmp/ on the path|Mac|
|event_platform=Mac event_simpleName=ProcessRollup2 (CommandLine="/tmp/*" OR CommandLine="/private/tmp/*")<br />\|dedup ComputerName<br />\|sort aip<br />\|table ComputerName aip CommandLine|Check the commandline performed|Mac|
|ComputerName = "*OP*" event_platform=Mac event_simpleName=ProcessRollup2 (sh OR launchctl)<br />\|transaction aid,ProcessGroupId_decimal<br />\|search sh launchctl<br />\|table ComputerName |Process tree with  sh and launchctl And view CC OP ComputerName|Mac|
|event_platform=Mac event_simpleName=ProcessRollup2 (sh OR launchctl)<br />\|transaction aid,ProcessGroupId_decimal<br />\|search sh launchctl<br />\|table ComputerName|Process tree with  sh and launchctl And view ComputerName|Mac|
|event_platform=Mac event_simpleName=ProcessRollup2 (CommandLine=sh* OR CommandLine=/bin/sh* OR CommandLine=/bin/bash)<br />\|search CommandLine="*"  NOT "*JAMF"<br />\|stats values(CommandLine) as Commands_List,count by aid,ComputerName<br />\|regex CommandLine!="(pid,pcpu,rss)"<br />\|search count>40|Count per Computer how many active shells and display the computer name with the list of actives shell|Mac|
|event_platform=Mac event_simpleName=*ProcessRollup2 CommandLine=* LaunchAgents* <br />\|dedup aid,CommandLine<br />\|makemv CommandLine delim=" " <br />\|eval CommandLine=mvfilter(match(CommandLine, ".*LaunchAgents.*"))<br />\|eval CommandLine=replace(CommandLine,"/Users/[a-z]+/", "/") <br />\|eval CommandLine=replace(CommandLine,"\"$", "") <br />\|stats count by CommandLine<br />\|sort count<br />|Rare agent launched|Cross Platform|

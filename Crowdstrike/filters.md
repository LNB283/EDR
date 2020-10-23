# Crowdstrike query filters 
### Description

##### A list of main filters I used when I created queries
| Filter | Description | 
| -------------- | :--------- |
|\|dedup xxxxxx|Remove duplicate results with the same xxxxx value|
|\|search <field> = "value" OR <field> = "value"|keep on the result the information that match with the "value"|
|\|sort <field1> , <field2>| sort result by field1 value in ascending order and field2 vlue by descending order|
|\|head <value>\return the first <value> results|
|\|tail <value>|returm the last <value> results|
|\|rare <field>|return the least common values of the <field>|
|\|top limit=<value> <field>|return the most common <value>  of the <field>|
|\|sendemail to="xxxx@xxxx.com" format=csv|receive the result by email and CSV file attached|
|\|reverse|Reverse the result order|

# dc_discovery
Gathers the following information from your domain controllers and outputs it to a CSV file in your Documents:
        - Server Name  
        - Domain Name  
        - Manufacturer  
        - Model  
        - Physical memory  
        - OS caption  
        - OS version  
        - # of cores  
        - CPU name  
        - IP Address  
        - DeviceID (hard drive letter)  
        - HD size in GB  
        - HD free space in GB  
        - HD % free  
        - NTDS and SYSVOL locations
		
# domain_discovery
Gathers the following information about your domain and outputs it to a file in your Documents:
		- Gets forest and domain information. 
		- Gets forest and domain functional levels. 
		- Gets domain creation date. 
		- Gets FSMO role holders. 
		- Gets AD schema version. 
		- Gets tombstone lifetime. 
		- Gets domain password policy. 
		- Gets AD backup information. 
		- Checks to see if AD Recycle Bin is enabled. 
		- Gets AD Sites and Subnets. 
		- Gets AD Site replication links. 
		- Gets AD trust information. 
		- Gets users and groups information. 
			- Number of users 
			- Number of groups 
			- Inactive accounts based on 30, 60, 90 days. 
		- Lists OUs with blocked inheritance. 
		- Lists unlinked GPOs. 
		- Lists duplicate SPNs.

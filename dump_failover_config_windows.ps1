# Ugly script that gathers cluster info for 
# Failover Cluster manager in Server 2012
# Failover ip's and the network configuration are both dropped into a backup file
# Cluster configuration is dropped into a separate file
#
# This probably should have been done better...
#
#
ipconfig /all | Out-File C:\Users\administrator\Downloads\ipconfig_pre.txt
Get-ClusterResource | where {$_.resourcetype -eq "IP Address"} | format-list | Out-File C:\Users\administrator\Downloads\ipconfig_pre.txt -Append
Import-Module -Name FailoverClusters
Get-Cluster | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt
Get-ClusterAccess | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterNode | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterQuorum | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterGroup | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Sort-Object -Property OwnerGroup, Name | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Sort-Object -Property OwnerGroup, Name | Get-ClusterResourceDependency | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append
Get-ClusterResource | Get-ClusterOwnerNode | Where-Object -FilterScript { $_.OwnerNodes.Count -ne ( Get-ClusterNode ).Count } | Format-List | Out-File C:\Users\Administrator\Downloads\cluster_info.txt -Append

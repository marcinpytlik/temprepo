/*
 SQLManiak Daily Health Check 1.5 / CSV (Log + Data File + Filegroup Capacity / v7 instance-scoped volume-policy actions + Linked Server diagnostics)
 SQL Server 2022+ (Windows / FCI)
 Core diagnostics read-only; opt-in history writes to SQLManiakHealthHistory only.
 No server configuration changes, job modifications, backup or maintenance.
 Execute in SSMS as a login with adequate server-level and msdb permissions.
 SQL Server 2022: VIEW SERVER PERFORMANCE STATE required for some DMVs;
 reading error logs requires VIEW ANY ERROR LOG or sufficient elevated rights.
 msdb SQL Agent history visibility depends on msdb SQLAgentReaderRole / sysadmin.
 All times are SQL Server local time.
*/
SET NOCOUNT ON;
DECLARE @Now datetime2(0) = SYSDATETIME();
DECLARE @Since datetime2(0) = DATEADD(HOUR,-24,@Now);
DECLARE @DiskWarningPercent decimal(5,2) = 20.0;
DECLARE @DiskCriticalPercent decimal(5,2) = 10.0;
DECLARE @LogWarningPercent decimal(5,2) = 75.0;
DECLARE @LogCriticalPercent decimal(5,2) = 90.0;
DECLARE @FullBackupMaxHours int = 26;
DECLARE @LogBackupMaxMinutes int = 30;
DECLARE @BlockingWarningSeconds int = 30;
DECLARE @RunningJobWarningMinutes int = 120;
DECLARE @ErrorLogFilesToScan int = 3; -- 0=current, 1..2 archived; max 7 supported
DECLARE @ShowErrorLogRows int = 200;
DECLARE @SaveHistory bit = 0;             -- 0: no writes; 1: save measurement if history DB deployed
DECLARE @MissingJobGraceMinutes int = 20; -- ignore runs scheduled in the last 20 minutes
DECLARE @JobStartToleranceMinutes int = 15;
DECLARE @FileGrowthWarningGB decimal(18,2) = 10.0;  -- net file size increase since previous sample
DECLARE @DiskDeclineWarningGBPerDay decimal(18,2) = 20.0;
DECLARE @HistoryDatabase sysname = N'SQLManiakHealthHistory';
DECLARE @AutoGrowthFrequentCount int = 10;   -- events in available 24-hour trace
DECLARE @AutoGrowthSlowMs decimal(19,2) = 1000.0; -- longest event >= 1 s
DECLARE @AutoGrowthGrowthWarningMB decimal(19,2) = 10240.0; -- >= 10 GB / 24 h
-- Oversized LOG candidates: thresholds are diagnostic, never trigger SHRINK.
-- Data file advisory: informational review threshold, NOT a mandatory split point.
DECLARE @DataFileReviewTB decimal(9,2) = 1.00;
DECLARE @DataFileMaxSizeWarningPercent decimal(5,2) = 90.00;
DECLARE @DataFileInternalFreeWarningPct decimal(5,2) = 10.00;
DECLARE @DataFileInternalFreeCriticalPct decimal(5,2) = 5.00;
DECLARE @DataFileHeadroomWarningGB decimal(19,2) = 100.00;
DECLARE @DataFileHeadroomCriticalGB decimal(19,2) = 25.00;
-- Filegroup-wide thresholds (GB) are capacity guardrails, not time-to-exhaustion predictions.
DECLARE @FilegroupHeadroomWarningGB decimal(19,2) = 500.00;
DECLARE @FilegroupHeadroomCriticalGB decimal(19,2) = 100.00;
DECLARE @FilegroupInternalFreeWarningPct decimal(5,2) = 10.00;
-- v4: minimum free space on an EXISTING volume to suggest altering MAXSIZE.
-- Separate from the filegroup overall reserve thresholds.
DECLARE @FilegroupActionMinimumVolumeFreeGB decimal(19,2) = 100.00;
-- v6: server/instance-specific capacity policy. NO GLOBAL DRIVE ASSUMPTIONS.
-- The same script can run on all servers. Match SQL instance using SERVERPROPERTY('ServerName')
-- (FCI virtual name, not the current physical node). A policy must be explicitly configured.
-- Units: GiB. SQL Server does not know storage-system expansion ceilings.
DECLARE @MinimumVolumeSafetyReserveGB decimal(19,2) = 150.00;
DECLARE @PolicyInstance sysname = CONVERT(sysname,SERVERPROPERTY('ServerName'));
CREATE TABLE #VolumePolicyCatalog
(
    InstanceName sysname NOT NULL,
    DriveLetter char(1) NOT NULL,
    CanExtend bit NOT NULL,
    MaxVolumeSizeGB decimal(19,2) NULL,
    Comment nvarchar(250) NOT NULL,
    PRIMARY KEY (InstanceName,DriveLetter),
    CHECK (MaxVolumeSizeGB IS NULL OR MaxVolumeSizeGB>0)
);
-- CONFIGURATION EXAMPLE. Replace instance names with the EXACT name printed
-- by SERVERPROPERTY('ServerName'), then uncomment. Other instances will not match.
-- The G/P/R example below is for the specific previously discussed FCI ONLY.
/*
INSERT #VolumePolicyCatalog(InstanceName,DriveLetter,CanExtend,MaxVolumeSizeGB,Comment)
VALUES
 (N'YOUR_FCI\YOUR_INSTANCE','G',0,NULL,N'Fixed volume; no storage extension'),
 (N'YOUR_FCI\YOUR_INSTANCE','P',1,6144.00,N'Max 6 TiB'),
 (N'YOUR_FCI\YOUR_INSTANCE','R',1,6144.00,N'Max 6 TiB'),
 (N'OTHER_SERVER','D',1,8192.00,N'Example: other server has independent limits');
*/
-- Filter policy to current instance; never reuse a drive-letter rule across instances.
CREATE TABLE #VolumePolicy
(
    DriveLetter char(1) NOT NULL PRIMARY KEY,
    CanExtend bit NOT NULL,
    MaxVolumeSizeGB decimal(19,2) NULL,
    Comment nvarchar(250) NOT NULL
);
INSERT #VolumePolicy (DriveLetter,CanExtend,MaxVolumeSizeGB,Comment)
SELECT DriveLetter,CanExtend,MaxVolumeSizeGB,Comment
FROM #VolumePolicyCatalog
WHERE InstanceName=@PolicyInstance;
-- v7: Linked Server inventory always passive; active probes explicitly opt-in.
DECLARE @EnableLinkedServerConnectivity bit = 0;
DECLARE @LinkedServerMaxConnectSeconds int = 15;
DECLARE @LinkedServerMaxQuerySeconds int = 30;
CREATE TABLE #LSProbeAllowlist(LinkedServer sysname NOT NULL PRIMARY KEY);
-- INSERT #LSProbeAllowlist VALUES (N'YOUR_LINKED_SERVER');
-- Targets with effective provider timeouts outside the above policy are skipped.
-- Do not change production timeout settings merely to enable this test.
DECLARE @LogOversizeMinGB decimal(19,2) = 4.0;
DECLARE @LogOversizeMaxUsedPercent decimal(9,2) = 10.0;
DECLARE @LogOversizeMinRatio decimal(12,2) = 1.0;

IF @ErrorLogFilesToScan NOT BETWEEN 1 AND 7
    THROW 50001, '@ErrorLogFilesToScan must be between 1 and 7.', 1;

CREATE TABLE #Alerts
(
    Id int IDENTITY(1,1) PRIMARY KEY,
    Severity varchar(8) NOT NULL,
    Area varchar(32) NOT NULL,
    ObjectName nvarchar(256) NULL,
    Details nvarchar(2000) NOT NULL
);

PRINT 'SQLManiak Daily Health Check -- '+CONVERT(varchar(19),@Now,120);

/* 1. Instance metadata */
BEGIN TRY
    SELECT '01 INSTANCE' AS Section,
           @@SERVERNAME AS SqlServerName,
           CONVERT(nvarchar(128),SERVERPROPERTY('ServerName')) AS ConnectedInstance,
           CONVERT(nvarchar(128),SERVERPROPERTY('ComputerNamePhysicalNetBIOS')) AS ActiveNode,
           CONVERT(int,SERVERPROPERTY('IsClustered')) AS IsClustered,
           CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')) AS ProductVersion,
           CONVERT(nvarchar(128),SERVERPROPERTY('ProductLevel')) AS ProductLevel,
           si.sqlserver_start_time AS SqlServerStartTime,
           @Since AS FromTime, @Now AS ToTime
    FROM sys.dm_os_sys_info si;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','INSTANCE',NULL,ERROR_MESSAGE());
END CATCH;

/* 1b. Service status; requires VIEW SERVER SECURITY STATE in SQL Server 2022 */
BEGIN TRY
    SELECT '01B SERVICES' AS Section,servicename,status_desc,startup_type_desc,
           last_startup_time,is_clustered,cluster_nodename
    FROM sys.dm_server_services;

    INSERT #Alerts
    SELECT 'CRITICAL','SERVICE',servicename,
           CONCAT('Service status: ',status_desc,'; startup: ',startup_type_desc)
    FROM sys.dm_server_services
    WHERE servicename LIKE N'SQL Server Agent%'
      AND status_desc <> N'Running';
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','SERVICE',NULL,ERROR_MESSAGE());
END CATCH;

/* 2. ERRORLOG files 0..N: scan archived files too, to handle restarts and cycling */
CREATE TABLE #ErrorLogRaw (LogDate datetime NULL, ProcessInfo nvarchar(100) NULL, [Text] nvarchar(max) NULL);
DECLARE @LogNumber int=0;
WHILE @LogNumber < @ErrorLogFilesToScan
BEGIN
    BEGIN TRY
        INSERT INTO #ErrorLogRaw (LogDate,ProcessInfo,[Text])
        EXEC master.dbo.xp_readerrorlog @LogNumber,1,NULL,NULL,@Since,@Now,N'desc';
    END TRY
    BEGIN CATCH
        INSERT #Alerts VALUES ('WARNING','ERRORLOG',CONCAT('Archive ',@LogNumber),ERROR_MESSAGE());
    END CATCH;
    SET @LogNumber+=1;
END;

SELECT DISTINCT LogDate,ProcessInfo,[Text]
INTO #ErrorLogMatches
FROM #ErrorLogRaw
WHERE LogDate >= @Since AND LogDate <= @Now
  AND (
      UPPER([Text]) LIKE '%ERROR:%' OR
      UPPER([Text]) LIKE '%SEVERITY:%' OR
      UPPER([Text]) LIKE '%FAILED%' OR
      UPPER([Text]) LIKE '%CORRUPT%' OR
      UPPER([Text]) LIKE '%SUSPECT%' OR
      UPPER([Text]) LIKE '%I/O REQUEST%' OR
      UPPER([Text]) LIKE '%DEADLOCK%' OR
      UPPER([Text]) LIKE '%STACK DUMP%' OR
      UPPER([Text]) LIKE '%EXCEPTION%' OR
      UPPER([Text]) LIKE '%TIMEOUT%' OR
      UPPER([Text]) LIKE '%ASSERTION%' OR
      UPPER([Text]) LIKE '%INSUFFICIENT%' OR
      UPPER([Text]) LIKE '%OPERATING SYSTEM ERROR%'
  );

SELECT TOP (@ShowErrorLogRows) '02 ERRORLOG' AS Section,
       LogDate, ProcessInfo, [Text] AS Message
FROM #ErrorLogMatches
ORDER BY LogDate DESC;

IF EXISTS (SELECT 1 FROM #ErrorLogMatches)
    INSERT #Alerts
    SELECT CASE WHEN EXISTS
      (SELECT 1 FROM #ErrorLogMatches
       WHERE UPPER([Text]) LIKE '%CORRUPT%' OR UPPER([Text]) LIKE '%SUSPECT%'
          OR UPPER([Text]) LIKE '%ERROR: 823%' OR UPPER([Text]) LIKE '%ERROR: 824%'
          OR UPPER([Text]) LIKE '%ERROR: 825%' OR UPPER([Text]) LIKE '%STACK DUMP%'
          OR UPPER([Text]) LIKE '%ASSERTION%') THEN 'CRITICAL' ELSE 'WARNING' END,
      'ERRORLOG', 'SQL Server ERRORLOG',
      CONCAT('Matching log entries in last 24h: ',(SELECT COUNT_BIG(*) FROM #ErrorLogMatches),
             '; displayed newest ',@ShowErrorLogRows,
             '. Pattern matching is indicative; review the messages.') ;

/* 3. All SQL Server Agent jobs and recent failures */
BEGIN TRY
    ;WITH Activity AS
    (
      SELECT a.job_id,a.start_execution_date,a.stop_execution_date,
             ROW_NUMBER() OVER (PARTITION BY a.job_id ORDER BY a.session_id DESC) AS rn
      FROM msdb.dbo.sysjobactivity a
    )
    SELECT j.job_id, j.name AS JobName, j.enabled AS IsEnabled,
           CASE WHEN a.start_execution_date IS NOT NULL AND a.stop_execution_date IS NULL
                THEN 1 ELSE 0 END AS IsRunning,
           a.start_execution_date AS RunningSince,
           h.LastRunTime, h.run_status AS LastRunStatus, h.message AS LastMessage,
           CASE WHEN h.run_status=0 THEN 'FAILED'
                WHEN h.run_status=1 THEN 'SUCCEEDED'
                WHEN h.run_status=2 THEN 'RETRY'
                WHEN h.run_status=3 THEN 'CANCELED'
                WHEN h.run_status=4 THEN 'IN PROGRESS'
                ELSE 'NEVER RUN / NO HISTORY' END AS LastRunResult
    INTO #Jobs
    FROM msdb.dbo.sysjobs j
    LEFT JOIN Activity a ON a.job_id=j.job_id AND a.rn=1
    OUTER APPLY
    (
       SELECT TOP (1) h.run_status,h.message,
              CASE WHEN h.run_date > 0 AND h.run_time >= 0
                   THEN msdb.dbo.agent_datetime(h.run_date,h.run_time) END AS LastRunTime
       FROM msdb.dbo.sysjobhistory h
       WHERE h.job_id=j.job_id AND h.step_id=0
       ORDER BY h.instance_id DESC
    ) h;

    SELECT '03 JOBS - CURRENT' AS Section, JobName, IsEnabled, IsRunning,
           RunningSince,LastRunTime,LastRunResult,LastMessage
    FROM #Jobs
    ORDER BY CASE WHEN IsRunning=1 THEN 0 WHEN LastRunStatus IN (0,3) THEN 1
                  WHEN IsEnabled=0 THEN 2 ELSE 3 END, JobName;

    INSERT #Alerts
    SELECT 'CRITICAL','JOB',JobName,
           CONCAT('Last completed execution: ',LastRunResult,' at ',
                  COALESCE(CONVERT(varchar(19),LastRunTime,120),'unknown'))
    FROM #Jobs WHERE IsEnabled=1 AND IsRunning=0 AND LastRunStatus=0;

    INSERT #Alerts
    SELECT 'WARNING','JOB',JobName,
           CONCAT('Running since ',CONVERT(varchar(19),RunningSince,120))
    FROM #Jobs
    WHERE IsRunning=1 AND RunningSince < DATEADD(MINUTE,-@RunningJobWarningMinutes,@Now);

    SELECT '04 JOBS - FAILED/CANCELED LAST 24H' AS Section,
           j.name AS JobName,h.step_id,h.step_name,
           CASE h.run_status WHEN 0 THEN 'FAILED' WHEN 3 THEN 'CANCELED' ELSE 'OTHER' END AS Status,
           x.RunTime,h.sql_message_id,h.sql_severity,h.message
    INTO #RecentJobFailures
    FROM msdb.dbo.sysjobhistory h
    JOIN msdb.dbo.sysjobs j ON j.job_id=h.job_id
    CROSS APPLY (SELECT CASE WHEN h.run_date > 0
                            THEN msdb.dbo.agent_datetime(h.run_date,h.run_time) END AS RunTime) x
    WHERE h.run_status IN (0,3) AND x.RunTime >= @Since AND x.RunTime <= @Now;

    SELECT * FROM #RecentJobFailures ORDER BY RunTime DESC,JobName,step_id;

    INSERT #Alerts
    SELECT 'CRITICAL','JOB HISTORY',JobName,
           CONCAT('Failed/canceled job execution(s) in 24h: ',COUNT(*),
                  '; newest: ',CONVERT(varchar(19),MAX(RunTime),120))
    FROM #RecentJobFailures
    WHERE step_id=0 -- job outcomes; individual failed steps are visible in detail
    GROUP BY JobName;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','JOBS',NULL,ERROR_MESSAGE());
END CATCH;

/* 4. Disks containing SQL data/log files -- NOT all OS volumes */
BEGIN TRY
    ;WITH Volumes AS
    (
      SELECT DISTINCT vs.volume_mount_point,vs.logical_volume_name,
             vs.total_bytes,vs.available_bytes
      FROM sys.master_files mf
      CROSS APPLY sys.dm_os_volume_stats(mf.database_id,mf.file_id) vs
      WHERE vs.total_bytes > 0
    )
    SELECT volume_mount_point,logical_volume_name,
           CAST(total_bytes / 1073741824.0 AS decimal(18,2)) AS TotalGB,
           CAST(available_bytes / 1073741824.0 AS decimal(18,2)) AS FreeGB,
           CAST(100.0*available_bytes / NULLIF(total_bytes,0) AS decimal(7,2)) AS FreePercent,
           total_bytes AS TotalBytes,available_bytes AS FreeBytes
    INTO #Volumes FROM Volumes;

    SELECT '05 DISK VOLUMES' AS Section,* FROM #Volumes ORDER BY FreePercent;

    INSERT #Alerts
    SELECT CASE WHEN FreePercent < @DiskCriticalPercent THEN 'CRITICAL' ELSE 'WARNING' END,
           'DISK',volume_mount_point,
           CONCAT('Free: ',FreeGB,' GB (',FreePercent,'%); total: ',TotalGB,' GB')
    FROM #Volumes WHERE FreePercent < @DiskWarningPercent;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','DISK',NULL,ERROR_MESSAGE());
END CATCH;

/* 5. Databases and backup history. No blanket policy for DIFF; user can inspect latest. */
BEGIN TRY
    SELECT d.name AS DatabaseName,d.state_desc,d.recovery_model_desc,
           d.is_read_only,d.is_in_standby,
           bFull.backup_finish_date AS LastFull,
           bDiff.backup_finish_date AS LastDiff,
           bLog.backup_finish_date AS LastLog
    INTO #Databases
    FROM sys.databases d
    OUTER APPLY
    (
      SELECT MAX(backup_finish_date) AS backup_finish_date
      FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='D'
    ) bFull
    OUTER APPLY
    (
      SELECT MAX(backup_finish_date) AS backup_finish_date
      FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='I'
    ) bDiff
    OUTER APPLY
    (
      SELECT MAX(backup_finish_date) AS backup_finish_date
      FROM msdb.dbo.backupset b WHERE b.database_name=d.name AND b.type='L'
    ) bLog
    WHERE d.source_database_id IS NULL; -- exclude snapshots

    SELECT '06 DATABASES + BACKUPS' AS Section,* FROM #Databases
    ORDER BY CASE WHEN state_desc<>'ONLINE' THEN 0 ELSE 1 END,DatabaseName;

    INSERT #Alerts
    SELECT 'CRITICAL','DATABASE',DatabaseName,CONCAT('Database state: ',state_desc)
    FROM #Databases WHERE state_desc<>'ONLINE' AND DatabaseName<>'tempdb';

    INSERT #Alerts
    SELECT 'WARNING','BACKUP FULL',DatabaseName,
           CONCAT('Last FULL: ',COALESCE(CONVERT(varchar(19),LastFull,120),'NOT FOUND IN MSDB'))
    FROM #Databases
    WHERE DatabaseName NOT IN ('tempdb','model') AND state_desc='ONLINE'
      AND is_read_only=0 AND (LastFull IS NULL OR LastFull<DATEADD(HOUR,-@FullBackupMaxHours,@Now));

    INSERT #Alerts
    SELECT 'WARNING','BACKUP LOG',DatabaseName,
           CONCAT('Last LOG: ',COALESCE(CONVERT(varchar(19),LastLog,120),'NOT FOUND IN MSDB'))
    FROM #Databases
    WHERE DatabaseName NOT IN ('master','model','msdb','tempdb')
      AND state_desc='ONLINE' AND is_read_only=0
      AND recovery_model_desc IN ('FULL','BULK_LOGGED')
      AND (LastLog IS NULL OR LastLog<DATEADD(MINUTE,-@LogBackupMaxMinutes,@Now));
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','BACKUP/DB',NULL,ERROR_MESSAGE());
END CATCH;

/* 6. Transaction log usage -- DBCC SQLPERF(LOGSPACE) is observational */
BEGIN TRY
    CREATE TABLE #LogSpace
    (
       DatabaseName sysname, LogSizeMB float, LogSpaceUsedPercent float, [Status] int
    );
    INSERT #LogSpace EXEC ('DBCC SQLPERF(LOGSPACE) WITH NO_INFOMSGS');

    SELECT '07 TRANSACTION LOG' AS Section,DatabaseName,
           CAST(LogSizeMB AS decimal(19,2)) AS LogSizeMB,
           CAST(LogSpaceUsedPercent AS decimal(7,2)) AS UsedPercent
    FROM #LogSpace ORDER BY LogSpaceUsedPercent DESC;

    INSERT #Alerts
    SELECT CASE WHEN LogSpaceUsedPercent>=@LogCriticalPercent THEN 'CRITICAL' ELSE 'WARNING' END,
           'TRANSACTION LOG',DatabaseName,
           CONCAT('Log used: ',CAST(LogSpaceUsedPercent AS decimal(7,2)),
                  '%; size ',CAST(LogSizeMB AS decimal(19,2)),' MB')
    FROM #LogSpace WHERE LogSpaceUsedPercent>=@LogWarningPercent;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','TRANSACTION LOG',NULL,ERROR_MESSAGE());
END CATCH;

/* 7. Current blocking, not historical blocking */
BEGIN TRY
    SELECT r.session_id AS BlockedSessionId,r.blocking_session_id AS BlockerSessionId,
           DB_NAME(r.database_id) AS DatabaseName,r.wait_type,
           CAST(r.wait_time/1000.0 AS decimal(15,1)) AS WaitSeconds,
           r.status,s.host_name,s.program_name,s.login_name,
           SUBSTRING(t.text, (r.statement_start_offset/2)+1,
                    ((CASE WHEN r.statement_end_offset=-1
                           THEN DATALENGTH(t.text)
                           ELSE r.statement_end_offset END-r.statement_start_offset)/2)+1)
           AS RunningStatement
    INTO #Blocking
    FROM sys.dm_exec_requests r
    JOIN sys.dm_exec_sessions s ON s.session_id=r.session_id
    OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
    WHERE r.blocking_session_id<>0 AND r.session_id<>@@SPID;

    SELECT '08 CURRENT BLOCKING' AS Section,* FROM #Blocking ORDER BY WaitSeconds DESC;

    INSERT #Alerts
    SELECT 'WARNING','BLOCKING',CONCAT('SPID ',BlockedSessionId),
           CONCAT('Blocked by SPID ',BlockerSessionId,' for ',WaitSeconds,
                  ' s; wait ',COALESCE(wait_type,'unknown'))
    FROM #Blocking WHERE WaitSeconds>=@BlockingWarningSeconds;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','BLOCKING',NULL,ERROR_MESSAGE());
END CATCH;

/* 8. File configuration and current allocations (always available, read-only) */
BEGIN TRY
    SELECT mf.database_id,mf.file_id,DB_NAME(mf.database_id) AS DatabaseName,
           mf.name AS LogicalFileName,mf.physical_name AS PhysicalName,mf.type_desc,
           CONVERT(bigint,mf.size) AS SizePages,
           CONVERT(decimal(19,2),mf.size/128.0) AS AllocatedMB,
           mf.growth,mf.is_percent_growth,mf.max_size,
           CASE WHEN mf.growth=0 THEN 'DISABLED'
                WHEN mf.is_percent_growth=1 THEN CONCAT(mf.growth,'%')
                ELSE CONCAT(CONVERT(decimal(19,2),mf.growth/128.0),' MB') END AS GrowthSetting,
           CASE WHEN mf.max_size=-1 THEN 'UNLIMITED'
                WHEN mf.max_size=0 THEN 'NO GROWTH'
                ELSE CONCAT(CONVERT(decimal(19,2),mf.max_size/128.0),' MB') END AS MaxSizeSetting
    INTO #CurrentFiles
    FROM sys.master_files mf;

    SELECT '09 FILES - SIZE AND AUTOGROWTH' AS Section,DatabaseName,LogicalFileName,
           type_desc,AllocatedMB,GrowthSetting,MaxSizeSetting,PhysicalName
    FROM #CurrentFiles ORDER BY DatabaseName,LogicalFileName;

    INSERT #Alerts
    SELECT 'WARNING','FILE CONFIG',DatabaseName + N'.' + LogicalFileName,
           CONCAT('Percentage autogrowth configured: ',GrowthSetting,'; size ',AllocatedMB,' MB')
    FROM #CurrentFiles WHERE is_percent_growth=1 AND growth>0;

    INSERT #Alerts
    SELECT 'WARNING','FILE CONFIG',DatabaseName + N'.' + LogicalFileName,
           CONCAT('Autogrowth disabled; allocated ',AllocatedMB,' MB')
    FROM #CurrentFiles WHERE growth=0 AND max_size<>0 AND database_id<>2;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','FILES',NULL,ERROR_MESSAGE());
END CATCH;

/* 9. Expected SQL Agent schedule occurrences within the last 24 hours.
   Covers one-time, daily, weekly and monthly absolute schedules.
   Sub-day intervals of >=60 seconds; startup/idle and <60s schedules are listed
   as unsupported for inference. This is a heuristic, not an Agent scheduler audit.
*/
BEGIN TRY
    CREATE TABLE #ScheduleCoverage(JobName sysname,ScheduleName sysname,Reason nvarchar(180));
    SELECT j.job_id,j.name AS JobName,s.schedule_id,s.name AS ScheduleName,
           s.freq_type,s.freq_interval,s.freq_subday_type,s.freq_subday_interval,
           s.freq_relative_interval,s.freq_recurrence_factor,
           s.active_start_date,s.active_end_date,s.active_start_time,s.active_end_time,
           s.enabled AS ScheduleEnabled,j.enabled AS JobEnabled
    INTO #ActiveSchedules
    FROM msdb.dbo.sysjobs j
    JOIN msdb.dbo.sysjobschedules js ON js.job_id=j.job_id
    JOIN msdb.dbo.sysschedules s ON s.schedule_id=js.schedule_id
    WHERE j.enabled=1 AND s.enabled=1;

    INSERT #ScheduleCoverage
    SELECT JobName,ScheduleName,
           CASE WHEN freq_type IN (64,128) THEN 'Startup/idle trigger (not time-based)'
                WHEN freq_type=32 THEN 'Monthly relative schedule: not evaluated (avoid false positives)'
                WHEN freq_type NOT IN (1,4,8,16) THEN 'Unsupported frequency type'
                WHEN freq_subday_type=2 AND freq_subday_interval<60 THEN 'Interval shorter than 60 seconds'
                WHEN freq_subday_type NOT IN (1,2,4,8) THEN 'Unsupported subday interval'
                WHEN freq_subday_interval<=0 AND freq_subday_type<>1 THEN 'Invalid subday interval'
                ELSE 'Unsupported calendar configuration' END
    FROM #ActiveSchedules
    WHERE freq_type NOT IN (1,4,8,16)
       OR freq_subday_type NOT IN (1,2,4,8)
       OR (freq_subday_type=2 AND freq_subday_interval<60)
       OR (freq_subday_type<>1 AND freq_subday_interval<=0);

    /* 0..1439 slots; one date + one previous day sufficient for 24h local period. */
    ;WITH N AS
    (
      SELECT TOP (1440) ROW_NUMBER() OVER(ORDER BY (SELECT NULL))-1 AS n
      FROM sys.all_objects a CROSS JOIN sys.all_objects b
    )
    SELECT n INTO #MinuteSlots FROM N;

    SELECT x.JobName,x.ScheduleName,x.job_id,x.schedule_id,x.ExpectedAt
    INTO #ExpectedRuns
    FROM #ActiveSchedules s
    CROSS JOIN (VALUES (CONVERT(date,@Now)),(DATEADD(day,-1,CONVERT(date,@Now)))) v(RunDay)
    CROSS JOIN #MinuteSlots n
    CROSS APPLY
    (
      SELECT CONVERT(date,CONVERT(char(8),s.active_start_date),112) AS StartDay,
             CONVERT(date,CONVERT(char(8),s.active_end_date),112) AS EndDay,
             DATEADD(SECOND,
               (s.active_start_time/10000)*3600 + ((s.active_start_time/100)%100)*60 + s.active_start_time%100,
               CONVERT(datetime2(0),v.RunDay)) AS DayStart,
             (s.active_end_time/10000)*3600 + ((s.active_end_time/100)%100)*60 + s.active_end_time%100 AS EndSecond,
             ((DATEDIFF(day,CONVERT(date,'19000107'),v.RunDay)%7+7)%7) AS SundayBasedWeekday,
             DATEDIFF(month,CONVERT(date,CONVERT(char(8),s.active_start_date),112),v.RunDay) AS MonthsElapsed
    ) d
    CROSS APPLY
    (
      SELECT DATEADD(SECOND,
        CASE s.freq_subday_type WHEN 1 THEN 0
             WHEN 2 THEN n.n*s.freq_subday_interval
             WHEN 4 THEN n.n*s.freq_subday_interval*60
             WHEN 8 THEN n.n*s.freq_subday_interval*3600 END,
        d.DayStart) AS ExpectedAt,
        s.JobName,s.ScheduleName,s.job_id,s.schedule_id
    ) x
    WHERE s.freq_type IN (1,4,8,16)
      AND s.freq_subday_type IN (1,2,4,8)
      AND (s.freq_subday_type=1 OR (s.freq_subday_interval>0 AND
                      (s.freq_subday_type<>2 OR s.freq_subday_interval>=60)))
      AND (s.freq_subday_type<>1 OR n.n=0)
      AND v.RunDay BETWEEN d.StartDay AND d.EndDay
      AND x.ExpectedAt BETWEEN @Since AND DATEADD(MINUTE,-@MissingJobGraceMinutes,@Now)
      AND DATEDIFF(SECOND,CONVERT(datetime2(0),v.RunDay),x.ExpectedAt)<=d.EndSecond
      AND (
          (s.freq_type=1 AND v.RunDay=d.StartDay)
          OR (s.freq_type=4 AND DATEDIFF(day,d.StartDay,v.RunDay)%NULLIF(s.freq_interval,0)=0)
          OR (s.freq_type=8 AND
                 (s.freq_interval & CONVERT(int,POWER(CONVERT(float,2),d.SundayBasedWeekday)))<>0
                 AND (DATEDIFF(day,
                       DATEADD(day,-(((DATEDIFF(day,CONVERT(date,'19000107'),d.StartDay)%7+7)%7)),d.StartDay),
                       DATEADD(day,-d.SundayBasedWeekday,v.RunDay))/7)
                      % NULLIF(s.freq_recurrence_factor,0)=0)
          OR (s.freq_type=16 AND d.MonthsElapsed%NULLIF(s.freq_recurrence_factor,0)=0
                 AND DAY(v.RunDay)=s.freq_interval)

      );

    /* Treat a scheduled slot as covered by any full job outcome that started
       close to the expected time, or by the job currently running. */
    SELECT e.JobName,e.ScheduleName,e.ExpectedAt
    INTO #MissedRuns
    FROM #ExpectedRuns e
    WHERE NOT EXISTS
    (
      SELECT 1 FROM msdb.dbo.sysjobhistory h
      WHERE h.job_id=e.job_id AND h.step_id=0 AND h.run_date>0
        AND msdb.dbo.agent_datetime(h.run_date,h.run_time)
            BETWEEN DATEADD(MINUTE,-@JobStartToleranceMinutes,e.ExpectedAt)
                AND DATEADD(MINUTE,@JobStartToleranceMinutes,e.ExpectedAt)
    )
    AND NOT EXISTS
    (
      SELECT 1 FROM #Jobs j
      WHERE j.job_id=e.job_id AND j.IsRunning=1
    )
    AND NOT EXISTS
    (
      SELECT 1 FROM msdb.dbo.sysjobhistory h
      CROSS APPLY (SELECT msdb.dbo.agent_datetime(h.run_date,h.run_time) AS StartedAt) t
      WHERE h.job_id=e.job_id AND h.step_id=0 AND h.run_date>0
        AND t.StartedAt<e.ExpectedAt
        AND DATEADD(SECOND,
             (h.run_duration/10000)*3600+((h.run_duration/100)%100)*60+h.run_duration%100,
             t.StartedAt) >=e.ExpectedAt
    );

    SELECT '10 SCHEDULED JOBS - POSSIBLY MISSED' AS Section,*
    FROM #MissedRuns ORDER BY ExpectedAt DESC,JobName;

    SELECT '10B SCHEDULES - NOT EVALUATED' AS Section,*
    FROM #ScheduleCoverage ORDER BY JobName,ScheduleName;

    INSERT #Alerts
    SELECT 'WARNING','MISSED JOB',JobName,
           CONCAT('Potentially missed scheduled starts: ',COUNT(*),
                  '; latest ',CONVERT(varchar(19),MAX(ExpectedAt),120),
                  '. Check Agent availability, overlaps and schedule changes.')
    FROM #MissedRuns GROUP BY JobName;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','JOB SCHEDULE',NULL,ERROR_MESSAGE());
END CATCH;

/* 10. Change history: previous sample, then optional save. */
BEGIN TRY
    IF OBJECT_ID(N'SQLManiakHealthHistory.hc.Sample',N'U') IS NULL
    BEGIN
        SELECT '11 HISTORY' AS Section,
               'History database not installed; file/disk trends and FCI owner changes unavailable' AS Message;
        INSERT #Alerts VALUES ('INFO','HISTORY',NULL,
             'Run SQLManiak_HealthHistory_Setup.sql once to enable historical comparisons.');
    END
    ELSE
    BEGIN
        DECLARE @InstanceName nvarchar(128) = CONVERT(nvarchar(128),SERVERPROPERTY('ServerName'));
        DECLARE @Node nvarchar(128) = CONVERT(nvarchar(128),SERVERPROPERTY('ComputerNamePhysicalNetBIOS'));
        DECLARE @IsClustered bit = CONVERT(bit,SERVERPROPERTY('IsClustered'));
        DECLARE @PreviousSampleId bigint,@PreviousAt datetime2(0),@PreviousNode nvarchar(128),@CurrentSampleId bigint;
        SELECT TOP (1) @PreviousSampleId=SampleId,@PreviousAt=CapturedAt,@PreviousNode=ActiveNode
        FROM SQLManiakHealthHistory.hc.Sample
        WHERE InstanceName=@InstanceName
        ORDER BY CapturedAt DESC,SampleId DESC;

        IF @IsClustered=1 AND @PreviousSampleId IS NOT NULL AND
           ISNULL(@Node,N'')<>ISNULL(@PreviousNode,N'')
            INSERT #Alerts VALUES ('WARNING','FCI FAILOVER',@InstanceName,
               CONCAT('Active node changed: ',COALESCE(@PreviousNode,'(unknown)'),
                      ' -> ',COALESCE(@Node,'(unknown)'),
                      '; prior sample ',CONVERT(varchar(19),@PreviousAt,120)));

        SELECT f.DatabaseName,f.LogicalFileName,f.type_desc,f.AllocatedMB AS CurrentMB,
               CONVERT(decimal(19,2),p.SizePages/128.0) AS PreviousMB,
               CONVERT(decimal(19,2),(f.SizePages-p.SizePages)/128.0) AS ChangeMB,
               @PreviousAt AS PreviousCapturedAt
        INTO #FileChanges
        FROM #CurrentFiles f
        LEFT JOIN SQLManiakHealthHistory.hc.FileSample p
          ON p.SampleId=@PreviousSampleId AND p.DatabaseId=f.database_id AND p.FileId=f.file_id
          AND p.PhysicalName=f.PhysicalName;

        SELECT '11 FILE GROWTH SINCE PRIOR SAMPLE' AS Section,*
        FROM #FileChanges ORDER BY ChangeMB DESC,DatabaseName;

        INSERT #Alerts
        SELECT 'WARNING','FILE GROWTH',DatabaseName + N'.' + LogicalFileName,
               CONCAT('Net allocated size increase: ',ChangeMB,' MB since ',
                      CONVERT(varchar(19),@PreviousAt,120))
        FROM #FileChanges WHERE ChangeMB>=@FileGrowthWarningGB*1024;

        SELECT v.volume_mount_point,v.TotalGB,v.FreeGB,v.FreePercent,
               CONVERT(decimal(19,2),p.FreeBytes/1073741824.0) AS PreviousFreeGB,
               CONVERT(decimal(19,2),(v.FreeBytes-p.FreeBytes)/1073741824.0) AS ChangeFreeGB,
               CASE WHEN DATEDIFF(MINUTE,@PreviousAt,@Now)>=60
                    THEN CONVERT(decimal(19,2),
                        (p.FreeBytes-v.FreeBytes)/1073741824.0*1440.0/
                        NULLIF(DATEDIFF(MINUTE,@PreviousAt,@Now),0)) END AS ConsumptionGBPerDay,
               @PreviousAt AS PreviousCapturedAt
        INTO #DiskTrend
        FROM #Volumes v
        LEFT JOIN SQLManiakHealthHistory.hc.VolumeSample p
          ON p.SampleId=@PreviousSampleId AND p.VolumeMountPoint=v.volume_mount_point;

        SELECT '12 DISK TREND SINCE PRIOR SAMPLE' AS Section,*
        FROM #DiskTrend ORDER BY ConsumptionGBPerDay DESC;

        INSERT #Alerts
        SELECT 'WARNING','DISK TREND',volume_mount_point,
               CONCAT('Estimated disk free-space decline: ',ConsumptionGBPerDay,
                      ' GB/day over sample interval; previous sample ',
                      CONVERT(varchar(19),@PreviousAt,120))
        FROM #DiskTrend WHERE ConsumptionGBPerDay>=@DiskDeclineWarningGBPerDay;

        IF @SaveHistory=1
        BEGIN
            BEGIN TRANSACTION;
            INSERT SQLManiakHealthHistory.hc.Sample(CapturedAt,InstanceName,IsClustered,ActiveNode)
            VALUES (@Now,@InstanceName,@IsClustered,@Node);
            SET @CurrentSampleId=SCOPE_IDENTITY();
            INSERT SQLManiakHealthHistory.hc.VolumeSample(SampleId,VolumeMountPoint,TotalBytes,FreeBytes)
            SELECT @CurrentSampleId,volume_mount_point,
                   TotalBytes,FreeBytes
            FROM #Volumes;
            INSERT SQLManiakHealthHistory.hc.FileSample
                (SampleId,DatabaseId,FileId,DatabaseName,LogicalFileName,PhysicalName,
                 TypeDesc,SizePages,Growth,IsPercentGrowth,MaxSize)
            SELECT @CurrentSampleId,database_id,file_id,DatabaseName,LogicalFileName,PhysicalName,
                   type_desc,SizePages,growth,is_percent_growth,max_size
            FROM #CurrentFiles;
            COMMIT TRANSACTION;
        END;
        SELECT '12B FCI ACTIVE NODE' AS Section,@InstanceName AS InstanceName,
               @IsClustered AS IsClustered,@PreviousNode AS PreviousNode,
               @Node AS CurrentNode,@PreviousAt AS PreviousCapturedAt,
               @CurrentSampleId AS SavedSampleId;
    END;
END TRY
BEGIN CATCH
    IF @@TRANCOUNT>0 ROLLBACK TRANSACTION;
    INSERT #Alerts VALUES ('WARNING','HISTORY',NULL,ERROR_MESSAGE());
END CATCH;


/* 12C. ACTUAL AUTOGROWTH EVENTS - read-only, default trace (92=data,93=log).
   This is not the same as net growth between file snapshots.
   Default Trace is a rolling/finite history; zero events is not proof of none.
   The section intentionally returns one row for EVERY current ROWS/LOG file.
   No XEvent session is created and no server settings are changed.
*/
BEGIN TRY
    DECLARE @AutoGrowthTracePath nvarchar(260) = NULL;
    DECLARE @AutoGrowthHistoryStatus varchar(32) = 'UNAVAILABLE';

    SELECT TOP (1) @AutoGrowthTracePath = [path]
    FROM sys.traces WHERE is_default = 1;

    -- Default Trace FileName contains the LOGICAL file name.
    CREATE TABLE #AutoGrowthEvents
    (
        DatabaseID int NULL,
        LogicalFileName nvarchar(260) COLLATE DATABASE_DEFAULT NULL,
        StartTime datetime NULL,
        EventClass int NOT NULL,
        GrowthMB decimal(19,2) NULL,
        DurationMs decimal(19,2) NULL
    );

    IF @AutoGrowthTracePath IS NOT NULL
    BEGIN
        BEGIN TRY
            INSERT #AutoGrowthEvents(DatabaseID,LogicalFileName,StartTime,EventClass,GrowthMB,DurationMs)
            SELECT t.DatabaseID,t.FileName,t.StartTime,t.EventClass,
                   CONVERT(decimal(19,2),CONVERT(float,t.IntegerData) / 128.0),
                   CONVERT(decimal(19,2),CONVERT(float,t.Duration) / 1000.0)
            FROM sys.fn_trace_gettable(@AutoGrowthTracePath,DEFAULT) AS t
            WHERE t.EventClass IN (92,93) AND t.StartTime IS NOT NULL;
            SET @AutoGrowthHistoryStatus = 'AVAILABLE_PARTIAL';
        END TRY
        BEGIN CATCH
            INSERT #Alerts VALUES ('WARNING','AUTOGROWTH',NULL,
                CONCAT('Cannot read Default Trace: ',ERROR_MESSAGE()));
        END CATCH;
    END
    ELSE
        INSERT #Alerts VALUES ('WARNING','AUTOGROWTH',NULL,
            'Default Trace unavailable: actual autogrowth events cannot be verified.');

    ;WITH EventAgg AS
    (
        SELECT DatabaseID,LogicalFileName,
               COUNT_BIG(*) AS EventsInAvailableTrace,
               SUM(CASE WHEN StartTime >= @Since AND StartTime <= @Now THEN CONVERT(bigint,1) ELSE CONVERT(bigint,0) END) AS Events24h,
               MAX(StartTime) AS LastAutoGrowth,
               SUM(CASE WHEN StartTime >= @Since AND StartTime <= @Now THEN GrowthMB ELSE CONVERT(decimal(19,2),0) END) AS GrowthMB24h,
               MAX(CASE WHEN StartTime >= @Since AND StartTime <= @Now THEN DurationMs END) AS MaxDurationMs24h
        FROM #AutoGrowthEvents
        GROUP BY DatabaseID,LogicalFileName
    )
    SELECT f.database_id,f.file_id,f.DatabaseName,f.LogicalFileName,f.type_desc AS FileType,
           f.PhysicalName,f.AllocatedMB,f.GrowthSetting,
           @AutoGrowthHistoryStatus AS HistoryStatus,
           CASE WHEN @AutoGrowthHistoryStatus <> 'AVAILABLE_PARTIAL' THEN NULL
                ELSE ISNULL(a.Events24h,CONVERT(bigint,0)) END AS Events24h,
           CASE WHEN @AutoGrowthHistoryStatus <> 'AVAILABLE_PARTIAL' THEN NULL
                ELSE ISNULL(a.GrowthMB24h,CONVERT(decimal(19,2),0)) END AS GrowthMB24h,
           CASE WHEN @AutoGrowthHistoryStatus <> 'AVAILABLE_PARTIAL' THEN NULL
                ELSE a.LastAutoGrowth END AS LastAutoGrowth,
           CASE WHEN @AutoGrowthHistoryStatus <> 'AVAILABLE_PARTIAL' THEN NULL
                ELSE a.MaxDurationMs24h END AS MaxDurationMs24h,
           CASE WHEN @AutoGrowthHistoryStatus <> 'AVAILABLE_PARTIAL' THEN NULL
                ELSE ISNULL(a.EventsInAvailableTrace,CONVERT(bigint,0)) END AS EventsInAvailableTrace
    INTO #AutoGrowthReport
    FROM #CurrentFiles AS f
    LEFT JOIN EventAgg AS a
      ON a.DatabaseID = f.database_id
     AND a.LogicalFileName = f.LogicalFileName COLLATE DATABASE_DEFAULT
    WHERE f.type_desc IN ('ROWS','LOG');

    SELECT '12C AUTOGROWTH EVENTS' AS Section,
           DatabaseName,LogicalFileName,FileType,AllocatedMB,GrowthSetting,
           HistoryStatus,Events24h,GrowthMB24h,LastAutoGrowth,MaxDurationMs24h,
           EventsInAvailableTrace,PhysicalName
    FROM #AutoGrowthReport
    ORDER BY Events24h DESC,DatabaseName,LogicalFileName;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT CASE WHEN Events24h >= @AutoGrowthFrequentCount * 3 THEN 'CRITICAL' ELSE 'WARNING' END,
           'AUTOGROWTH',CONCAT(DatabaseName,'.',LogicalFileName),
           CONCAT('Frequent autogrowth: ',Events24h,' events in available 24h; ',
                  GrowthMB24h,' MB total; longest ',COALESCE(CONVERT(varchar(40),MaxDurationMs24h),'n/a'),' ms')
    FROM #AutoGrowthReport
    WHERE Events24h >= @AutoGrowthFrequentCount;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'WARNING','AUTOGROWTH',CONCAT(DatabaseName,'.',LogicalFileName),
           CONCAT('Slow autogrowth: maximum ',MaxDurationMs24h,
                  ' ms in available 24h; events: ',Events24h)
    FROM #AutoGrowthReport
    WHERE MaxDurationMs24h >= @AutoGrowthSlowMs
      AND (Events24h < @AutoGrowthFrequentCount OR Events24h IS NULL);

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'WARNING','AUTOGROWTH',CONCAT(DatabaseName,'.',LogicalFileName),
           CONCAT('High autogrowth volume: ',GrowthMB24h,
                  ' MB in available 24h; events: ',Events24h)
    FROM #AutoGrowthReport
    WHERE GrowthMB24h >= @AutoGrowthGrowthWarningMB
      AND (Events24h < @AutoGrowthFrequentCount OR Events24h IS NULL)
      AND (MaxDurationMs24h < @AutoGrowthSlowMs OR MaxDurationMs24h IS NULL);
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','AUTOGROWTH',NULL,
        CONCAT('Autogrowth audit failed: ',ERROR_MESSAGE()));
END CATCH;

/* 12D. LOG OVERSIZING ANALYSIS -- READ ONLY, no shrink, no file changes.
   DBCC SQLPERF(LOGSPACE) reports used LOG for all databases at this instant.
   VLF diagnostics are best effort; privileges may restrict sys.dm_db_log_info.
   A large, mostly unused LOG is a review candidate, NOT automatic evidence
   that shrinking is safe. Daily restores can recreate source file sizes.
*/
BEGIN TRY
    CREATE TABLE #LogSpaceAudit
    (
        DatabaseName sysname COLLATE DATABASE_DEFAULT NOT NULL,
        LogSizeMB float NULL,
        LogSpaceUsedPercent float NULL,
        [Status] int NULL
    );

    INSERT #LogSpaceAudit(DatabaseName,LogSizeMB,LogSpaceUsedPercent,[Status])
    EXEC ('DBCC SQLPERF(LOGSPACE) WITH NO_INFOMSGS');

    ;WITH FileTotals AS
    (
        SELECT database_id,
               SUM(CASE WHEN [type] = 0 THEN CONVERT(bigint,[size]) ELSE CONVERT(bigint,0) END) / 128.0 AS DataSizeMB,
               SUM(CASE WHEN [type] = 1 THEN CONVERT(bigint,[size]) ELSE CONVERT(bigint,0) END) / 128.0 AS LogSizeMB
        FROM sys.master_files
        GROUP BY database_id
    )
    SELECT d.database_id,
           d.name AS DatabaseName,
           d.recovery_model_desc AS RecoveryModel,
           d.log_reuse_wait_desc AS LogReuseWait,
           CONVERT(decimal(19,2),f.DataSizeMB / 1024.0) AS DataSizeGB,
           CONVERT(decimal(19,2),f.LogSizeMB / 1024.0) AS LogSizeGB,
           CONVERT(decimal(19,2),f.LogSizeMB / NULLIF(f.DataSizeMB,0)) AS LogToDataRatio,
           CONVERT(decimal(9,2),l.LogSpaceUsedPercent) AS LogUsedPercent,
           CONVERT(decimal(19,2),l.LogSizeMB * l.LogSpaceUsedPercent / 100.0) AS UsedLogMB,
           CONVERT(decimal(19,2),l.LogSizeMB * (100.0 - l.LogSpaceUsedPercent) / 100.0) AS FreeLogMB,
           CONVERT(int,NULL) AS TotalVLF,
           CONVERT(int,NULL) AS ActiveVLF,
           CONVERT(decimal(19,2),NULL) AS ActiveVLFSizeMB,
           CONVERT(varchar(32),'NOT_CHECKED') AS VLFStatus
    INTO #LogOversize
    FROM sys.databases AS d
    INNER JOIN FileTotals AS f ON d.database_id = f.database_id
    INNER JOIN #LogSpaceAudit AS l ON l.DatabaseName = d.name COLLATE DATABASE_DEFAULT
    WHERE d.state = 0
      AND f.LogSizeMB > 0
      AND (f.LogSizeMB > f.DataSizeMB OR
           (f.LogSizeMB >= @LogOversizeMinGB * 1024.0 AND l.LogSpaceUsedPercent <= @LogOversizeMaxUsedPercent));

    -- VLF enumeration restricted to selected candidates (rather than every database).
    DECLARE @VlfDbId int;
    DECLARE vlf_candidates CURSOR LOCAL FAST_FORWARD FOR
        SELECT database_id FROM #LogOversize ORDER BY database_id;
    OPEN vlf_candidates;
    FETCH NEXT FROM vlf_candidates INTO @VlfDbId;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            UPDATE r
               SET TotalVLF = x.TotalVLF,
                   ActiveVLF = x.ActiveVLF,
                   ActiveVLFSizeMB = x.ActiveVLFSizeMB,
                   VLFStatus = 'OK'
            FROM #LogOversize AS r
            CROSS APPLY
            (
                SELECT COUNT(*) AS TotalVLF,
                       SUM(CASE WHEN vlf_active = 1 THEN 1 ELSE 0 END) AS ActiveVLF,
                       CONVERT(decimal(19,2),SUM(CASE WHEN vlf_active = 1 THEN vlf_size_mb ELSE 0 END)) AS ActiveVLFSizeMB
                FROM sys.dm_db_log_info(@VlfDbId)
            ) AS x
            WHERE r.database_id = @VlfDbId;
        END TRY
        BEGIN CATCH
            UPDATE #LogOversize SET VLFStatus = 'UNAVAILABLE' WHERE database_id = @VlfDbId;
        END CATCH;
        FETCH NEXT FROM vlf_candidates INTO @VlfDbId;
    END;
    CLOSE vlf_candidates;
    DEALLOCATE vlf_candidates;

    SELECT '12D LOG OVERSIZING' AS Section,
           DatabaseName,RecoveryModel,DataSizeGB,LogSizeGB,LogToDataRatio,
           LogUsedPercent,UsedLogMB,FreeLogMB,LogReuseWait,
           TotalVLF,ActiveVLF,ActiveVLFSizeMB,VLFStatus,
           CASE WHEN LogSizeGB >= @LogOversizeMinGB
                     AND LogToDataRatio > @LogOversizeMinRatio
                     AND LogUsedPercent <= @LogOversizeMaxUsedPercent
                THEN 'REVIEW - OVERSIZED LOG'
                ELSE 'INFO' END AS Assessment
    FROM #LogOversize
    ORDER BY LogSizeGB DESC,DatabaseName;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'WARNING','LOG OVERSIZING',DatabaseName,
           CONCAT('LOG ',LogSizeGB,' GB vs DATA ',DataSizeGB,
                  ' GB; used ',LogUsedPercent,'%; free ~',FreeLogMB,
                  ' MB; reuse wait ',LogReuseWait,
                  '. Review workload and next RESTORE; no automatic SHRINK.')
    FROM #LogOversize
    WHERE LogSizeGB >= @LogOversizeMinGB
      AND LogToDataRatio > @LogOversizeMinRatio
      AND LogUsedPercent <= @LogOversizeMaxUsedPercent;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','LOG OVERSIZING',NULL,
        CONCAT('LOG oversizing audit unavailable: ',ERROR_MESSAGE()));
END CATCH;

/* 12E. LOG CAPACITY & SHRINK ANALYSIS (read-only, no SHRINK commands).
   Scope: databases selected by 12D plus msdb and ReportServerTempDB.
   LOG utilization is database-wide; file position and growth are per LOG file.
   PotentialShrinkMB is an upper-bound VLF-tail estimate, NOT guaranteed savings.
   Current VLF position may change while workloads execute.
   File-size trend is optional; used-log trend is NOT persisted by this script.
*/
BEGIN TRY
    CREATE TABLE #LogCapacity
    (
        database_id int NOT NULL,
        file_id int NOT NULL,
        DatabaseName sysname NOT NULL,
        LogicalFileName sysname NOT NULL,
        PhysicalName nvarchar(260) NULL,
        CurrentSizeMB decimal(19,2) NULL,
        LogUsedPercent decimal(9,2) NULL,
        LogReuseWait nvarchar(60) NULL,
        GrowthSetting nvarchar(80) NULL,
        GrowthMBAtCurrentSize decimal(19,2) NULL,
        TotalVLF int NULL,
        ActiveVLF int NULL,
        LastActiveVLFEndMB decimal(19,2) NULL,
        PotentialShrinkMB decimal(19,2) NULL,
        PreviousSizeMB decimal(19,2) NULL,
        PreviousCapturedAt datetime2(0) NULL,
        VLFStatus varchar(32) NOT NULL DEFAULT ('NOT_CHECKED'),
        PRIMARY KEY (database_id,file_id)
    );

    INSERT #LogCapacity
       (database_id,file_id,DatabaseName,LogicalFileName,PhysicalName,
        CurrentSizeMB,LogUsedPercent,LogReuseWait,GrowthSetting,GrowthMBAtCurrentSize)
    SELECT mf.database_id,mf.file_id,d.name,mf.name,mf.physical_name,
           CONVERT(decimal(19,2),mf.size/128.0),
           CONVERT(decimal(9,2),l.LogSpaceUsedPercent),d.log_reuse_wait_desc,
           CASE WHEN mf.growth=0 THEN N'DISABLED'
                WHEN mf.is_percent_growth=1 THEN CONCAT(mf.growth,N'%')
                ELSE CONCAT(CONVERT(decimal(19,2),mf.growth/128.0),N' MB') END,
           CASE WHEN mf.growth=0 THEN CONVERT(decimal(19,2),0)
                WHEN mf.is_percent_growth=1
                    THEN CONVERT(decimal(19,2),(mf.size/128.0)*mf.growth/100.0)
                ELSE CONVERT(decimal(19,2),mf.growth/128.0) END
    FROM sys.master_files AS mf
    JOIN sys.databases AS d ON d.database_id=mf.database_id AND d.state=0
    LEFT JOIN #LogSpaceAudit AS l ON l.DatabaseName=d.name COLLATE DATABASE_DEFAULT
    WHERE mf.type_desc='LOG'
      AND (d.database_id IN (SELECT database_id FROM #LogOversize)
           OR d.name IN (N'msdb',N'ReportServerTempDB'));

    -- One DMV evaluation per selected database, aggregated per logical log file.
    DECLARE @CapacityDatabaseId int;
    DECLARE capacity_databases CURSOR LOCAL FAST_FORWARD FOR
        SELECT DISTINCT database_id FROM #LogCapacity ORDER BY database_id;
    OPEN capacity_databases;
    FETCH NEXT FROM capacity_databases INTO @CapacityDatabaseId;
    WHILE @@FETCH_STATUS=0
    BEGIN
        BEGIN TRY
            ;WITH VLFPerFile AS
            (
                SELECT file_id,
                       COUNT(*) AS TotalVLF,
                       SUM(CASE WHEN vlf_active=1 THEN 1 ELSE 0 END) AS ActiveVLF,
                       MAX(CASE WHEN vlf_active=1
                                THEN vlf_begin_offset/1048576.0 + vlf_size_mb
                           END) AS LastActiveVLFEndMB
                FROM sys.dm_db_log_info(@CapacityDatabaseId)
                GROUP BY file_id
            )
            UPDATE lc
               SET TotalVLF=v.TotalVLF,
                   ActiveVLF=v.ActiveVLF,
                   LastActiveVLFEndMB=CONVERT(decimal(19,2),v.LastActiveVLFEndMB),
                   PotentialShrinkMB=CASE
                       WHEN v.ActiveVLF=0 THEN lc.CurrentSizeMB
                       WHEN v.LastActiveVLFEndMB>=lc.CurrentSizeMB THEN CONVERT(decimal(19,2),0)
                       ELSE CONVERT(decimal(19,2),lc.CurrentSizeMB-v.LastActiveVLFEndMB)
                   END,
                   VLFStatus='OK'
            FROM #LogCapacity AS lc
            JOIN VLFPerFile AS v ON v.file_id=lc.file_id
            WHERE lc.database_id=@CapacityDatabaseId;
        END TRY
        BEGIN CATCH
            UPDATE #LogCapacity SET VLFStatus='UNAVAILABLE'
            WHERE database_id=@CapacityDatabaseId;
        END CATCH;
        FETCH NEXT FROM capacity_databases INTO @CapacityDatabaseId;
    END;
    CLOSE capacity_databases;
    DEALLOCATE capacity_databases;

    -- #FileChanges exists only if the optional history database was readable.
    IF OBJECT_ID('tempdb..#FileChanges') IS NOT NULL
    BEGIN
        EXEC sys.sp_executesql N'
            UPDATE lc
               SET PreviousSizeMB=fc.PreviousMB,
                   PreviousCapturedAt=fc.PreviousCapturedAt
            FROM #LogCapacity AS lc
            JOIN #FileChanges AS fc
              ON fc.DatabaseName=lc.DatabaseName
             AND fc.LogicalFileName=lc.LogicalFileName
             AND fc.type_desc=''LOG'';';
    END;

    SELECT '12E LOG CAPACITY & SHRINK ANALYSIS' AS Section,
           DatabaseName,LogicalFileName,PhysicalName,CurrentSizeMB,
           LogUsedPercent,CONVERT(decimal(9,2),100.0-LogUsedPercent) AS LogFreePercent,
           LogReuseWait,TotalVLF,ActiveVLF,LastActiveVLFEndMB,
           PotentialShrinkMB,
           CONVERT(decimal(19,2),PotentialShrinkMB/1024.0) AS PotentialShrinkGB,
           GrowthSetting,GrowthMBAtCurrentSize,
           PreviousSizeMB,
           CASE WHEN PreviousSizeMB IS NOT NULL
                THEN CONVERT(decimal(19,2),CurrentSizeMB-PreviousSizeMB) END AS SizeChangeSincePriorMB,
           PreviousCapturedAt,VLFStatus,
           CASE WHEN VLFStatus<>'OK' THEN 'VLF DATA UNAVAILABLE'
                WHEN PotentialShrinkMB>=1024 AND LogUsedPercent<=10
                     THEN 'REVIEW SHRINK CANDIDATE'
                WHEN GrowthSetting LIKE N'%[%]' THEN 'REVIEW GROWTH SETTING'
                ELSE 'MONITOR' END AS Assessment
    FROM #LogCapacity
    ORDER BY PotentialShrinkMB DESC,DatabaseName,LogicalFileName;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'WARNING','LOG CAPACITY',CONCAT(DatabaseName,N'.',LogicalFileName),
           CONCAT('Potential removable VLF tail ~',PotentialShrinkMB,
                  ' MB (upper-bound estimate); used ',LogUsedPercent,
                  '%, active VLF ',ActiveVLF,
                  ', reuse wait ',LogReuseWait,
                  '. Review historical peak before any manual SHRINK.')
    FROM #LogCapacity
    WHERE VLFStatus='OK' AND PotentialShrinkMB>=1024
      AND LogUsedPercent<=10;
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','LOG CAPACITY',NULL,
        CONCAT('Log capacity analysis unavailable: ',ERROR_MESSAGE()));
END CATCH;

/* 12F. DATA FILE CAPACITY & EXPANSION ADVISORY (read-only).
   FILEPROPERTY(name,'SpaceUsed') is evaluated IN EACH database; returns allocated
   pages, not the true size of rows. NULL/failed access is explicitly UNKNOWN.
   Free INSIDE the file is NOT additional space on the volume.
   Headroom per file = internal free + possible autogrowth bounded by file MAXSIZE
   and volume free; it is a point-in-time estimate and NOT additive across files
   that share the same volume. FILEGROUP details are presented to aid decisions.
   A size >=1 TB triggers review only; recommendation to ADD FILE requires
   demonstrated risk, and is conditional on suitable storage and filegroup.
*/
BEGIN TRY
    CREATE TABLE #InFileUsage
    (
        database_id int NOT NULL,
        file_id int NOT NULL,
        data_space_id int NULL,
        SpaceUsedPages bigint NULL,
        ReadStatus varchar(16) NOT NULL,
        PRIMARY KEY(database_id,file_id)
    );

    DECLARE @DbId int, @DbName sysname, @UsageSql nvarchar(max);
    DECLARE DataFileUsageCursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT database_id,name FROM sys.databases
        WHERE database_id>4 AND state=0 AND HAS_DBACCESS(name)=1;
    OPEN DataFileUsageCursor;
    FETCH NEXT FROM DataFileUsageCursor INTO @DbId,@DbName;
    WHILE @@FETCH_STATUS=0
    BEGIN
        BEGIN TRY
            SET @UsageSql=N'USE '+QUOTENAME(@DbName)+N';
                INSERT INTO #InFileUsage(database_id,file_id,data_space_id,SpaceUsedPages,ReadStatus)
                SELECT @DatabaseId,file_id,data_space_id,
                       CONVERT(bigint,FILEPROPERTY(name,''SpaceUsed'')),
                       CASE WHEN FILEPROPERTY(name,''SpaceUsed'') IS NULL
                            THEN ''UNKNOWN'' ELSE ''OK'' END
                FROM sys.database_files WHERE type=0;';
            EXEC sys.sp_executesql @UsageSql,N'@DatabaseId int',@DatabaseId=@DbId;
        END TRY
        BEGIN CATCH
            INSERT #Alerts(Severity,Area,ObjectName,Details)
            VALUES ('WARNING','DATA FILE CAPACITY',@DbName,
                    CONCAT('Cannot measure in-file usage: ',ERROR_MESSAGE()));
        END CATCH;
        FETCH NEXT FROM DataFileUsageCursor INTO @DbId,@DbName;
    END;
    CLOSE DataFileUsageCursor;
    DEALLOCATE DataFileUsageCursor;

    ;WITH DataFiles AS
    (
        SELECT f.database_id,f.file_id,f.DatabaseName,f.LogicalFileName,
               f.PhysicalName,f.SizePages,f.AllocatedMB,f.GrowthSetting,
               f.MaxSizeSetting,f.growth,f.max_size,f.is_percent_growth,
               iu.data_space_id,iu.SpaceUsedPages,iu.ReadStatus,
               CONVERT(decimal(19,2),iu.SpaceUsedPages/128.0) AS UsedInsideMB,
               CONVERT(decimal(19,2),(f.SizePages-iu.SpaceUsedPages)/128.0) AS FreeInsideMB,
               CONVERT(decimal(9,2),100.0*(f.SizePages-iu.SpaceUsedPages)/
                     NULLIF(CONVERT(decimal(28,4),f.SizePages),0)) AS FreeInsidePct,
               COUNT(*) OVER (PARTITION BY f.database_id,iu.data_space_id) AS FilegroupFileCount,
               COUNT(*) OVER (PARTITION BY f.database_id) AS DatabaseDataFileCount,
               SUM(f.AllocatedMB) OVER (PARTITION BY f.database_id,iu.data_space_id) AS FilegroupAllocatedMB,
               SUM(CONVERT(decimal(19,2),(f.SizePages-iu.SpaceUsedPages)/128.0))
                   OVER (PARTITION BY f.database_id,iu.data_space_id) AS FilegroupFreeInsideMB,
               SUM(f.AllocatedMB) OVER (PARTITION BY f.database_id) AS DatabaseAllocatedMB,
               CASE WHEN f.max_size>0
                    THEN CONVERT(decimal(9,2),100.0*f.SizePages/NULLIF(CONVERT(decimal(28,4),f.max_size),0)) END AS MaxUsedPct,
               vs.volume_mount_point AS VolumeMountPoint,
               vs.volume_id AS VolumeId,
               CONVERT(decimal(19,2),vs.total_bytes/1073741824.0) AS VolumeTotalGB,
               UPPER(LEFT(f.PhysicalName,1)) AS DriveLetter,
               CONVERT(decimal(19,2),vs.available_bytes/1073741824.0) AS VolumeFreeGB,
               CONVERT(decimal(9,2),100.0*vs.available_bytes/
                     NULLIF(CONVERT(decimal(28,4),vs.total_bytes),0)) AS VolumeFreePct
        FROM #CurrentFiles f
        JOIN sys.databases d ON d.database_id=f.database_id AND d.state=0
        LEFT JOIN #InFileUsage iu ON iu.database_id=f.database_id AND iu.file_id=f.file_id
        OUTER APPLY sys.dm_os_volume_stats(f.database_id,f.file_id) vs
        WHERE f.type_desc='ROWS' AND f.database_id>4
    )
    SELECT df.*,
           CASE WHEN df.growth=0 OR df.max_size=0 THEN CONVERT(decimal(19,2),0)
                WHEN df.max_size>0 THEN CONVERT(decimal(19,2),
                     CASE WHEN df.max_size>df.SizePages THEN (df.max_size-df.SizePages)/128.0 ELSE 0 END)
                ELSE CONVERT(decimal(19,2),NULL) END AS ConfiguredGrowthRoomMB,
           CASE WHEN df.growth=0 OR df.max_size=0 THEN CONVERT(decimal(19,2),0)
                WHEN df.VolumeFreeGB IS NULL THEN NULL
                WHEN df.max_size>0 THEN CONVERT(decimal(19,2),
                     CASE WHEN (df.max_size-df.SizePages)/128.0 < 0 THEN 0
                          WHEN (df.max_size-df.SizePages)/128.0 < df.VolumeFreeGB*1024
                          THEN (df.max_size-df.SizePages)/128.0
                          ELSE df.VolumeFreeGB*1024 END)
                ELSE CONVERT(decimal(19,2),df.VolumeFreeGB*1024) END AS PotentialGrowthMB
    INTO #DataFileCapacityBase
    FROM DataFiles df;

    -- v5: scope drive policy to actual Windows drive-letter paths only.
    -- No match for mount points / UNC paths: those require explicit policy mapping.
    ALTER TABLE #DataFileCapacityBase ADD
        PolicyCanExtend bit NULL,
        PolicyMaxVolumeGB decimal(19,2) NULL,
        PolicyRemainingExpandGB decimal(19,2) NULL,
        PolicyStatus varchar(45) NULL;

    UPDATE b SET
      PolicyCanExtend=p.CanExtend,
      PolicyMaxVolumeGB=p.MaxVolumeSizeGB,
      PolicyRemainingExpandGB=CASE
         WHEN p.DriveLetter IS NULL OR b.VolumeTotalGB IS NULL THEN NULL
         WHEN p.CanExtend=0 THEN CONVERT(decimal(19,2),0)
         WHEN p.MaxVolumeSizeGB IS NULL THEN NULL
         WHEN b.VolumeTotalGB>=p.MaxVolumeSizeGB THEN CONVERT(decimal(19,2),0)
         ELSE CONVERT(decimal(19,2),p.MaxVolumeSizeGB-b.VolumeTotalGB) END,
      PolicyStatus=CASE
         WHEN b.PhysicalName NOT LIKE '[A-Za-z]:\%' THEN 'UNMAPPED VOLUME PATH'
         WHEN p.DriveLetter IS NULL THEN 'NO POLICY CONFIGURED'
         WHEN b.VolumeId IS NULL OR b.VolumeTotalGB IS NULL THEN 'VOLUME METADATA UNKNOWN'
         WHEN p.CanExtend=0 THEN 'FIXED - NO EXTENSION'
         WHEN p.MaxVolumeSizeGB IS NULL THEN 'LIMIT UNKNOWN'
         WHEN b.VolumeTotalGB>p.MaxVolumeSizeGB+1 THEN 'CURRENT SIZE ABOVE POLICY LIMIT'
         WHEN b.VolumeTotalGB>=p.MaxVolumeSizeGB THEN 'POLICY LIMIT REACHED'
         ELSE 'EXTENSION POSSIBLE (NOT YET ALLOCATED)' END
    FROM #DataFileCapacityBase b
    LEFT JOIN #VolumePolicy p ON p.DriveLetter=b.DriveLetter
         AND b.PhysicalName LIKE '[A-Za-z]:\%';

    -- Diagnostic visibility for all policy drives (including R: with no database files).
    SELECT '12G0 VOLUME EXPANSION POLICY' AS Section,
           @PolicyInstance AS InstanceName,
           p.DriveLetter+':' AS Volume,
           p.CanExtend,p.MaxVolumeSizeGB,
           v.CurrentVolumeGB,v.CurrentFreeGB,
           CASE WHEN v.CurrentVolumeGB IS NULL THEN NULL
                WHEN p.CanExtend=0 THEN CONVERT(decimal(19,2),0)
                WHEN p.MaxVolumeSizeGB IS NULL THEN NULL
                WHEN v.CurrentVolumeGB>=p.MaxVolumeSizeGB THEN CONVERT(decimal(19,2),0)
                ELSE CONVERT(decimal(19,2),p.MaxVolumeSizeGB-v.CurrentVolumeGB) END AS PossibleVolumeExtensionGB,
           CASE WHEN v.CurrentVolumeGB IS NULL THEN 'NOT OBSERVED - CHECK VOLUME'
                WHEN p.CanExtend=0 THEN 'NO EXTENSION ALLOWED'
                WHEN p.MaxVolumeSizeGB IS NULL THEN 'POLICY LIMIT UNKNOWN'
                WHEN v.CurrentVolumeGB>p.MaxVolumeSizeGB+1 THEN 'ABOVE CONFIGURED POLICY LIMIT'
                WHEN v.CurrentVolumeGB>=p.MaxVolumeSizeGB THEN 'AT POLICY LIMIT'
                ELSE 'EXTENSION POSSIBLE - REQUIRES STORAGE CHANGE' END AS PolicyAssessment,
           p.Comment
    FROM #VolumePolicy p
    OUTER APPLY
    (
       SELECT MAX(VolumeTotalGB) AS CurrentVolumeGB,
              MIN(VolumeFreeGB) AS CurrentFreeGB
       FROM #DataFileCapacityBase b
       WHERE b.DriveLetter=p.DriveLetter AND b.PhysicalName LIKE '[A-Za-z]:\%'
    ) v
    ORDER BY p.DriveLetter;

    IF NOT EXISTS (SELECT 1 FROM #VolumePolicy)
       SELECT '12G0 POLICY STATUS' AS Section, @PolicyInstance AS InstanceName,
              'NO INSTANCE POLICY CONFIGURED' AS PolicyStatus,
              'Configure #VolumePolicyCatalog for this exact SQL instance; disk/FCI expansion rights are UNKNOWN.' AS Explanation;

    -- Read filegroup names from the database context, rather than master metadata.
    CREATE TABLE #FgNames(database_id int NOT NULL,data_space_id int NOT NULL,
                          FilegroupName sysname NOT NULL,PRIMARY KEY(database_id,data_space_id));
    DECLARE FgCursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT database_id,name FROM sys.databases
        WHERE database_id>4 AND state=0 AND HAS_DBACCESS(name)=1;
    OPEN FgCursor;
    FETCH NEXT FROM FgCursor INTO @DbId,@DbName;
    WHILE @@FETCH_STATUS=0
    BEGIN
        BEGIN TRY
            SET @UsageSql=N'USE '+QUOTENAME(@DbName)+N';
                INSERT INTO #FgNames(database_id,data_space_id,FilegroupName)
                SELECT @DatabaseId,data_space_id,name FROM sys.filegroups;';
            EXEC sys.sp_executesql @UsageSql,N'@DatabaseId int',@DatabaseId=@DbId;
        END TRY
        BEGIN CATCH
            INSERT #Alerts(Severity,Area,ObjectName,Details)
            VALUES ('WARNING','DATA FILE CAPACITY',@DbName,
                    CONCAT('Cannot read filegroup names: ',ERROR_MESSAGE()));
        END CATCH;
        FETCH NEXT FROM FgCursor INTO @DbId,@DbName;
    END;
    CLOSE FgCursor;
    DEALLOCATE FgCursor;

    ;WITH Classified AS
    (
        SELECT b.*, fgn.FilegroupName AS ResolvedFilegroupName,
               CONVERT(decimal(19,2),b.AllocatedMB/1048576.0) AS FileSizeTB,
               CONVERT(decimal(19,2),b.DatabaseAllocatedMB/1048576.0) AS DatabaseSizeTB,
               CONVERT(decimal(19,2),b.FilegroupAllocatedMB/1048576.0) AS FilegroupSizeTB,
               CONVERT(decimal(9,2),100.0*b.FilegroupFreeInsideMB/
                   NULLIF(b.FilegroupAllocatedMB,0)) AS FilegroupFreeInsidePct,
               CONVERT(decimal(19,2),
                   CASE WHEN b.FreeInsideMB IS NULL OR b.PotentialGrowthMB IS NULL THEN NULL
                        ELSE (b.FreeInsideMB+b.PotentialGrowthMB)/1024.0 END) AS FileHeadroomGB,
               CASE WHEN b.SpaceUsedPages IS NULL THEN 'UNKNOWN - IN-FILE USAGE'
                    WHEN b.FreeInsideMB<0 THEN 'UNKNOWN - INCONSISTENT USAGE'
                    WHEN b.PotentialGrowthMB IS NULL THEN 'UNKNOWN - VOLUME CAPACITY'
                    WHEN (b.FreeInsideMB+b.PotentialGrowthMB)/1024.0<@DataFileHeadroomCriticalGB
                         AND b.FreeInsidePct<@DataFileInternalFreeCriticalPct THEN 'CRITICAL - EXHAUSTION RISK'
                    WHEN (b.FreeInsideMB+b.PotentialGrowthMB)/1024.0<@DataFileHeadroomWarningGB
                         OR (b.FreeInsidePct<@DataFileInternalFreeWarningPct AND
                             (b.growth=0 OR b.max_size=0 OR b.VolumeFreePct<@DiskWarningPercent OR
                              b.MaxUsedPct>=@DataFileMaxSizeWarningPercent)) THEN 'WARNING - LIMITED HEADROOM'
                    WHEN b.AllocatedMB>=@DataFileReviewTB*1048576.0 THEN 'REVIEW - LARGE DATA FILE'
                    ELSE 'OK' END AS Assessment
        FROM #DataFileCapacityBase b
        LEFT JOIN #FgNames fgn ON fgn.database_id=b.database_id AND fgn.data_space_id=b.data_space_id
    )
    SELECT DatabaseName,LogicalFileName,PhysicalName,
           ResolvedFilegroupName AS FilegroupName,FilegroupFileCount,DatabaseDataFileCount,
           FileSizeTB,DatabaseSizeTB,FilegroupSizeTB,FilegroupFreeInsideMB,FilegroupFreeInsidePct,
           AllocatedMB,UsedInsideMB,FreeInsideMB,FreeInsidePct,
           GrowthSetting,MaxSizeSetting,MaxUsedPct,ConfiguredGrowthRoomMB,
           VolumeMountPoint,VolumeFreeGB,VolumeFreePct,
           VolumeTotalGB,DriveLetter,PolicyCanExtend,PolicyMaxVolumeGB,
           PolicyRemainingExpandGB,PolicyStatus,
           FileHeadroomGB,Assessment,
           CONVERT(decimal(19,2),NULL) AS FilegroupHeadroomGB,
           CONVERT(varchar(48),NULL) AS FilegroupAssessment,
           CONVERT(nvarchar(800),NULL) AS FilegroupRecommendation,
           CONVERT(varchar(800),CASE
             WHEN Assessment LIKE 'CRITICAL%' AND FilegroupFileCount=1
               THEN 'URGENT: file has little effective headroom. Secure capacity; if this filegroup needs more space, ADD FILE to this filegroup on a verified suitable volume or extend/remove existing growth limits. Validate storage, growth and backup first.'
             WHEN Assessment LIKE 'CRITICAL%'
               THEN 'URGENT: secure filegroup capacity; check headroom of OTHER files in this filegroup and volume sharing before deciding whether ADD FILE is required. Extend volume/MAXSIZE or add a file on suitable storage.'
             WHEN Assessment LIKE 'WARNING%' AND FilegroupFileCount=1
               THEN 'Plan extra filegroup capacity now: consider ADD FILE on suitable storage, or increase existing file/volume growth limits. Confirm projected growth and backup capacity.'
             WHEN Assessment LIKE 'WARNING%'
               THEN 'Plan capacity: inspect other files in the SAME filegroup; add a file only if aggregate usable capacity is insufficient. Check volumes and MAXSIZE.'
             WHEN Assessment LIKE 'UNKNOWN%'
               THEN 'Measurement incomplete: review access/volume metadata and rerun; do not infer free space or recommend ADD FILE from this sample.'
             WHEN Assessment LIKE 'REVIEW%'
               THEN 'File >=1 TB: review growth trends, volume and filegroup layout; file size alone is NOT a reason to ADD FILE.'
             ELSE 'No immediate capacity action based on this point-in-time sample.' END) AS Recommendation
    INTO #DataFileAdvisory
    FROM Classified;

    /* 12G. Filegroup-wide capacity. Every volume is counted ONCE per filegroup.
       This is an upper-bound point-in-time estimate: other databases/filegroups
       on the same volume compete for the same space. It is NOT a reservation.
       A missing file measurement/volume ID causes UNKNOWN, never a fabricated zero.
       No growth-rate forecast is asserted without historical in-file used-space data.
    */
    ;WITH PerVolume AS
    (
        SELECT database_id,data_space_id,VolumeId,
               MIN(VolumeFreeGB) AS VolumeFreeGB,
               SUM(CASE WHEN growth=0 OR max_size=0 THEN CONVERT(decimal(28,2),0)
                        WHEN max_size=-1 THEN CONVERT(decimal(28,2),0)
                        WHEN max_size>0 AND max_size>SizePages
                          THEN CONVERT(decimal(28,2),(max_size-SizePages)/128.0/1024.0)
                        ELSE CONVERT(decimal(28,2),0) END) AS LimitedGrowthGB,
               MAX(CASE WHEN growth>0 AND max_size=-1 THEN 1 ELSE 0 END) AS HasUnlimited,
               MAX(CASE WHEN growth>0 AND max_size<>0 THEN 1 ELSE 0 END) AS HasGrowable
        FROM #DataFileCapacityBase
        GROUP BY database_id,data_space_id,VolumeId
    ),
    VolumeCapacity AS
    (
        SELECT database_id,data_space_id,VolumeId,
               CASE WHEN HasGrowable=0 THEN CONVERT(decimal(28,2),0)
                    WHEN VolumeId IS NULL OR VolumeFreeGB IS NULL THEN NULL
                    WHEN HasUnlimited=1 OR LimitedGrowthGB>=VolumeFreeGB
                      THEN CONVERT(decimal(28,2),VolumeFreeGB)
                    ELSE LimitedGrowthGB END AS GrowthGB,
               CASE WHEN HasGrowable=1 AND (VolumeId IS NULL OR VolumeFreeGB IS NULL)
                    THEN 1 ELSE 0 END AS UnknownGrowth
        FROM PerVolume
    ),
    FGFiles AS
    (
        SELECT database_id,data_space_id,MAX(DatabaseName) AS DatabaseName,
               COUNT(*) AS FileCount,
               SUM(CONVERT(decimal(28,2),AllocatedMB))/1024.0 AS AllocatedGB,
               SUM(CONVERT(decimal(28,2),FreeInsideMB))/1024.0 AS InternalFreeGB,
               SUM(CASE WHEN SpaceUsedPages IS NULL OR FreeInsideMB<0
                             OR data_space_id IS NULL THEN 1 ELSE 0 END) AS UnknownFiles,
               SUM(CASE WHEN max_size=0 OR growth=0 OR
                           (max_size>0 AND max_size<=SizePages) THEN 1 ELSE 0 END)
                       AS GrowthBlockedFileCount
        FROM #DataFileCapacityBase
        GROUP BY database_id,data_space_id
    ),
    FGVolumes AS
    (
        SELECT database_id,data_space_id,COUNT(*) AS VolumeCount,
               SUM(GrowthGB) AS GrowthGB,
               SUM(UnknownGrowth) AS UnknownVolumes
        FROM VolumeCapacity
        GROUP BY database_id,data_space_id
    ),
    FGCalculated AS
    (
        SELECT f.database_id,f.data_space_id,f.DatabaseName,n.FilegroupName,
               f.FileCount,f.AllocatedGB,f.InternalFreeGB,
               CONVERT(decimal(9,2),100.0*f.InternalFreeGB/NULLIF(f.AllocatedGB,0)) AS InternalFreePct,
               v.VolumeCount,f.GrowthBlockedFileCount,
               CASE WHEN f.UnknownFiles>0 OR v.UnknownVolumes>0 OR
                              n.FilegroupName IS NULL THEN NULL
                    ELSE CONVERT(decimal(19,2),v.GrowthGB) END AS AdditionalGrowthGB,
               CASE WHEN f.UnknownFiles>0 OR v.UnknownVolumes>0 OR
                              n.FilegroupName IS NULL THEN NULL
                    ELSE CONVERT(decimal(19,2),f.InternalFreeGB+v.GrowthGB) END AS EffectiveHeadroomGB,
               f.UnknownFiles,v.UnknownVolumes
        FROM FGFiles f
        JOIN FGVolumes v ON v.database_id=f.database_id
                        AND (v.data_space_id=f.data_space_id OR
                             (v.data_space_id IS NULL AND f.data_space_id IS NULL))
        LEFT JOIN #FgNames n ON n.database_id=f.database_id AND n.data_space_id=f.data_space_id
    )
    SELECT c.*,
           CASE WHEN EffectiveHeadroomGB IS NULL THEN 'UNKNOWN - INCOMPLETE CAPACITY DATA'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomCriticalGB
                  THEN 'CRITICAL - FILEGROUP HEADROOM'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomWarningGB
                  THEN 'WARNING - FILEGROUP HEADROOM'
                WHEN InternalFreePct<@FilegroupInternalFreeWarningPct
                  THEN 'REVIEW - LOW INTERNAL FREE'
                ELSE 'OK - CAPACITY' END AS FilegroupAssessment,
           CONVERT(nvarchar(800),CASE
                WHEN EffectiveHeadroomGB IS NULL THEN
                   'VERIFY METADATA: file usage, filegroup mapping or volume capacity unavailable; do not assume free capacity.'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomCriticalGB AND AdditionalGrowthGB=0 THEN
                   'URGENT: SECURE STORAGE. Current file growth is blocked or no volume capacity remains; extend volumes or review MAXSIZE, or ADD FILE on another suitable volume.'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomCriticalGB THEN
                   'URGENT: ADD CAPACITY. Validate projected growth and per-volume limits; extend existing files/volumes or ADD FILE to this filegroup on suitable storage.'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomWarningGB AND AdditionalGrowthGB=0 THEN
                   'PLAN CAPACITY: no additional file growth available. Review MAXSIZE and storage, or ADD FILE on a suitable volume.'
                WHEN EffectiveHeadroomGB<@FilegroupHeadroomWarningGB THEN
                   'PLAN CAPACITY: small filegroup-wide reserve. Review volume sharing and growth rates; extend existing capacity or ADD FILE if needed.'
                WHEN InternalFreePct<@FilegroupInternalFreeWarningPct THEN
                   'MONITOR: internal free is low, but estimated filegroup growth capacity exists. Review real growth trends and competing workloads.'
                ELSE 'CAPACITY SUFFICIENT under static thresholds; monitor growth and verify shared-volume contention.'
            END) AS FilegroupRecommendation
    INTO #FilegroupCapacity
    FROM FGCalculated c;

    -- v5: policy-aware telemetry by EXISTING volume, counted once per FG.
    -- Planned extension capacity is deliberately NOT included in EffectiveHeadroomGB.
    -- VolumePolicy figures describe future infrastructure options, not an allocation guarantee.
    ALTER TABLE #FilegroupCapacity ADD
        FixedVolumeCount int NULL,
        ExpandableVolumeCount int NULL,
        PolicyUnmappedFileCount int NULL,
        VolumeAtPolicyLimitCount int NULL,
        PotentialVolumeExtensionGB decimal(19,2) NULL,
        CurrentVolumesLowFreeCount int NULL,
        PlannedStorageAction varchar(40) NULL,
        PlannedStorageReason nvarchar(1000) NULL;

    ;WITH DistinctFGVolumes AS
    (
       SELECT database_id,data_space_id,VolumeId,
              MAX(PolicyCanExtend * 1) AS CanExtend,
              MAX(PolicyRemainingExpandGB) AS ExpandableGB,
              MIN(VolumeFreeGB) AS FreeGB,
              MAX(CASE WHEN PolicyStatus='POLICY LIMIT REACHED' THEN 1 ELSE 0 END) AS AtLimit,
              MAX(CASE WHEN PolicyStatus NOT IN
                    ('FIXED - NO EXTENSION','POLICY LIMIT REACHED',
                     'EXTENSION POSSIBLE (NOT YET ALLOCATED)')
                       OR PolicyStatus IS NULL THEN 1 ELSE 0 END) AS Unmapped
       FROM #DataFileCapacityBase
       GROUP BY database_id,data_space_id,VolumeId
    ), VolumePolicyAggregate AS
    (
       SELECT database_id,data_space_id,
              SUM(CASE WHEN CanExtend=0 THEN 1 ELSE 0 END) AS FixedVolumeCount,
              SUM(CASE WHEN CanExtend=1 THEN 1 ELSE 0 END) AS ExpandableVolumeCount,
              SUM(CASE WHEN Unmapped=1 THEN 1 ELSE 0 END) AS PolicyUnmappedFileCount,
              SUM(CASE WHEN AtLimit=1 THEN 1 ELSE 0 END) AS VolumeAtPolicyLimitCount,
              SUM(ExpandableGB) AS PotentialVolumeExtensionGB,
              SUM(CASE WHEN FreeGB<@MinimumVolumeSafetyReserveGB THEN 1 ELSE 0 END)
                  AS CurrentVolumesLowFreeCount
       FROM DistinctFGVolumes
       GROUP BY database_id,data_space_id
    )
    UPDATE fg SET
       FixedVolumeCount=v.FixedVolumeCount,
       ExpandableVolumeCount=v.ExpandableVolumeCount,
       PolicyUnmappedFileCount=v.PolicyUnmappedFileCount,
       VolumeAtPolicyLimitCount=v.VolumeAtPolicyLimitCount,
       PotentialVolumeExtensionGB=v.PotentialVolumeExtensionGB,
       CurrentVolumesLowFreeCount=v.CurrentVolumesLowFreeCount
    FROM #FilegroupCapacity fg
    JOIN VolumePolicyAggregate v ON v.database_id=fg.database_id
      AND (v.data_space_id=fg.data_space_id OR
           (v.data_space_id IS NULL AND fg.data_space_id IS NULL));

    /* v4: actionable filegroup decision. Inspect all existing files (not a single
       'problem' file), identifying which limitation actually applies.
       IMPORTANT: these flags represent only EXISTING file locations; we cannot
       discover or validate a NEW suitable volume from sys.dm_os_volume_stats.
       Action codes are recommendations, never executable DDL.
       We only suggest a capacity change when the static filegroup threshold is
       breached; low internal free by itself is not evidence of imminent exhaustion.
    */
    ALTER TABLE #FilegroupCapacity ADD
        RecommendedAction varchar(40) NULL,
        ActionReason nvarchar(1000) NULL,
        MaxSizeLimitedFiles int NULL,
        GrowthDisabledFiles int NULL,
        FilesWithGrowthPotential int NULL,
        FilesWithMaxSizeAndVolumeRoom int NULL,
        FilesWithLowVolumeFree int NULL,
        EstimatedGrowthLimitGB decimal(19,2) NULL;

    ;WITH Flags AS
    (
        SELECT database_id,data_space_id,
               SUM(CASE WHEN max_size>0 AND max_size<=SizePages THEN 1 ELSE 0 END)
                   AS MaxSizeLimitedFiles,
               SUM(CASE WHEN growth=0 OR max_size=0 THEN 1 ELSE 0 END)
                   AS GrowthDisabledFiles,
               SUM(CASE WHEN growth>0 AND max_size<>0 AND
                                  (max_size=-1 OR max_size>SizePages) AND
                                  VolumeFreeGB>0 THEN 1 ELSE 0 END)
                   AS FilesWithGrowthPotential,
               SUM(CASE WHEN max_size>0 AND max_size<=SizePages
                                   AND VolumeFreeGB>=@FilegroupActionMinimumVolumeFreeGB
                             THEN 1 ELSE 0 END) AS FilesWithMaxSizeAndVolumeRoom,
               SUM(CASE WHEN VolumeFreeGB<@FilegroupActionMinimumVolumeFreeGB
                             THEN 1 ELSE 0 END) AS FilesWithLowVolumeFree,
               SUM(CASE WHEN max_size>0 AND max_size>SizePages
                             THEN CONVERT(decimal(28,2),(max_size-SizePages)/128.0/1024.0)
                             ELSE CONVERT(decimal(28,2),0) END) AS GrowthLimitGB
        FROM #DataFileCapacityBase
        GROUP BY database_id,data_space_id
    )
    UPDATE fg
        SET MaxSizeLimitedFiles=f.MaxSizeLimitedFiles,
            GrowthDisabledFiles=f.GrowthDisabledFiles,
            FilesWithGrowthPotential=f.FilesWithGrowthPotential,
            FilesWithMaxSizeAndVolumeRoom=f.FilesWithMaxSizeAndVolumeRoom,
            FilesWithLowVolumeFree=f.FilesWithLowVolumeFree,
            EstimatedGrowthLimitGB=CONVERT(decimal(19,2),f.GrowthLimitGB)
    FROM #FilegroupCapacity fg
    JOIN Flags f ON f.database_id=fg.database_id
                AND (f.data_space_id=fg.data_space_id OR
                    (f.data_space_id IS NULL AND fg.data_space_id IS NULL));

    /* The action is deterministic and ordered. Do not confuse existing file
       autogrowth capacity with immediately unallocated pages inside files.
       'ADD FILE' always requires validation of an actual target volume and
       storage/backup implications by an administrator.
    */
    UPDATE fg
      SET RecommendedAction = CASE
            WHEN EffectiveHeadroomGB IS NULL THEN 'INSUFFICIENT DATA'
            WHEN PolicyUnmappedFileCount>0 THEN 'VERIFY VOLUME POLICY'
            WHEN EffectiveHeadroomGB>=@FilegroupHeadroomWarningGB
                 THEN 'CAPACITY SUFFICIENT'
            WHEN FilesWithMaxSizeAndVolumeRoom>0
                 THEN 'INCREASE MAXSIZE'
            WHEN FilesWithGrowthPotential>0 AND AdditionalGrowthGB>0
                 THEN 'EXTEND EXISTING FILE'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 AND ExpandableVolumeCount>0 AND PotentialVolumeExtensionGB>0
                 THEN 'EXTEND VOLUME'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 AND FixedVolumeCount>0 AND ExpandableVolumeCount=0
                 THEN 'STORAGE LIMIT REACHED'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 THEN 'EXTEND STORAGE REQUIRED'
            WHEN AdditionalGrowthGB=0
                 THEN 'ADD FILE RECOMMENDED'
            ELSE 'CAPACITY PLANNING REQUIRED' END,
          ActionReason = CONVERT(nvarchar(1000),CASE
            WHEN EffectiveHeadroomGB IS NULL
                 THEN 'Incomplete in-file/volume/filegroup measurements. Recheck permissions and metadata; no change is justified from this sample.'
            WHEN PolicyUnmappedFileCount>0
                 THEN 'Policy missing for one or more existing filegroup volumes on THIS instance. Current disk free is measurable, but storage extension actions are NOT verified. Set an instance-specific policy.'
            WHEN EffectiveHeadroomGB>=@FilegroupHeadroomWarningGB
                 THEN 'Static effective filegroup reserve is at/above the configured threshold. Check actual growth trend; this is not a days-to-full forecast.'
            WHEN FilesWithMaxSizeAndVolumeRoom>0
                 THEN 'At least one existing file is at MAXSIZE with >= action minimum free GB on its current volume. Validate competing allocations, autogrowth settings and storage before changing MAXSIZE.'
            WHEN FilesWithGrowthPotential>0 AND AdditionalGrowthGB>0
                 THEN 'Existing file(s) may grow on current volume(s). Plan file growth and validate volume sharing, growth setting and filesystem capacity; adding a file is not automatically necessary.'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 AND ExpandableVolumeCount>0 AND PotentialVolumeExtensionGB>0
                 THEN 'Storage policy permits extending an EXISTING filegroup volume within its ceiling. This extension is not provisioned yet; obtain infrastructure approval and verify file MAXSIZE and filesystem capacity.'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 AND FixedVolumeCount>0 AND ExpandableVolumeCount=0
                 THEN 'Existing filegroup volumes cannot be expanded by configured policy. Verify a NEW suitable volume and its accessibility on all FCI nodes before considering ADD FILE.'
            WHEN AdditionalGrowthGB=0 AND FilesWithLowVolumeFree>0
                 THEN 'Current free storage is constrained; verify which specific volumes are expandable and whether a separate target volume is available.'
            WHEN AdditionalGrowthGB=0
                 THEN 'No configured growth reserve in the filegroup. Consider ADD FILE only on independently verified suitable storage after assessing MAXSIZE, disabled growth and workload; no new-volume availability is confirmed.'
            ELSE 'Small filegroup reserve; inspect file and volume limits and recent measured growth before any ALTER DATABASE.' END)
    FROM #FilegroupCapacity fg;

    -- Advisory separate from filegroup capacity status: an OK aggregate MUST NOT
    -- mask a fixed nearly full G: volume or MAXSIZE restrictions on existing files.
    UPDATE fg SET
       PlannedStorageAction = CASE
          WHEN EffectiveHeadroomGB IS NULL OR PolicyUnmappedFileCount>0
             THEN 'VERIFY POLICY AND METADATA'
          WHEN FixedVolumeCount>0 AND CurrentVolumesLowFreeCount>0
             THEN 'PROTECT FIXED VOLUME'
          WHEN ExpandableVolumeCount>0 AND PotentialVolumeExtensionGB>0
             THEN 'VOLUME EXTENSION AVAILABLE'
          WHEN VolumeAtPolicyLimitCount>0
             THEN 'STORAGE LIMIT REACHED'
          ELSE 'MONITOR' END,
       PlannedStorageReason = CASE
          WHEN EffectiveHeadroomGB IS NULL OR PolicyUnmappedFileCount>0
             THEN 'Unmapped or incomplete volume metadata: no policy-backed storage recommendation can be confirmed.'
          WHEN FixedVolumeCount>0 AND CurrentVolumesLowFreeCount>0
             THEN 'At least one non-expandable volume has less free space than the configured safety reserve. Plan capacity on a suitable separately verified volume or file location.'
          WHEN ExpandableVolumeCount>0 AND PotentialVolumeExtensionGB>0
             THEN 'An existing FG volume can be extended within the declared policy, subject to storage/FCI approval; future capacity is excluded from current headroom.'
          WHEN VolumeAtPolicyLimitCount>0
             THEN 'At least one volume is already at configured ceiling; no more volume extension is assumed.'
          ELSE 'Monitor used-space trend and existing MAXSIZE constraints.' END
    FROM #FilegroupCapacity fg;

    UPDATE fg
       SET FilegroupRecommendation = CONVERT(nvarchar(800),
           CONCAT(RecommendedAction, ': ', ActionReason))
    FROM #FilegroupCapacity fg;

    -- Add aggregate context to every row of 12F; replace generic warnings with
    -- a specific recommendation driven by all files in the same filegroup.
    UPDATE d SET
        d.FilegroupHeadroomGB=g.EffectiveHeadroomGB,
        d.FilegroupAssessment=g.FilegroupAssessment,
        d.FilegroupRecommendation=g.FilegroupRecommendation,
        d.Recommendation=CASE
           WHEN g.FilegroupAssessment IS NULL OR g.FilegroupAssessment LIKE 'UNKNOWN%'
               THEN 'Filegroup capacity UNKNOWN: verify usage and volume metadata before planning ADD FILE.'
           WHEN d.Assessment LIKE 'WARNING%' OR d.Assessment LIKE 'CRITICAL%'
               THEN CONVERT(varchar(800),g.FilegroupRecommendation)
           ELSE d.Recommendation END
    FROM #DataFileAdvisory d
    JOIN #FilegroupCapacity g ON g.DatabaseName=d.DatabaseName
           AND g.FilegroupName=d.FilegroupName;

    SELECT '12G FILEGROUP CAPACITY & ACTIONS' AS Section,
           DatabaseName,FilegroupName,FileCount,VolumeCount,
           CONVERT(decimal(19,2),AllocatedGB/1024.0) AS AllocatedTB,
           InternalFreeGB,InternalFreePct,AdditionalGrowthGB,EffectiveHeadroomGB,
           GrowthBlockedFileCount,UnknownFiles,UnknownVolumes,
           MaxSizeLimitedFiles,GrowthDisabledFiles,FilesWithGrowthPotential,
           FilesWithMaxSizeAndVolumeRoom,FilesWithLowVolumeFree,
           RecommendedAction,ActionReason,
           FixedVolumeCount,ExpandableVolumeCount,PolicyUnmappedFileCount,
           VolumeAtPolicyLimitCount,PotentialVolumeExtensionGB,
           CurrentVolumesLowFreeCount,
           PlannedStorageAction,PlannedStorageReason,
           FilegroupAssessment,FilegroupRecommendation
    FROM #FilegroupCapacity
    ORDER BY CASE WHEN FilegroupAssessment LIKE 'CRITICAL%' THEN 0
                  WHEN FilegroupAssessment LIKE 'WARNING%' THEN 1
                  WHEN FilegroupAssessment LIKE 'UNKNOWN%' THEN 2
                  WHEN FilegroupAssessment LIKE 'REVIEW%' THEN 3 ELSE 4 END,
             EffectiveHeadroomGB,DatabaseName,FilegroupName;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT CASE WHEN FilegroupAssessment LIKE 'CRITICAL%' THEN 'CRITICAL'
                WHEN FilegroupAssessment LIKE 'WARNING%' OR FilegroupAssessment LIKE 'UNKNOWN%'
                    THEN 'WARNING' ELSE 'INFO' END,
           'FILEGROUP CAPACITY',CONCAT(DatabaseName,N'.',COALESCE(FilegroupName,N'?')),
           CONCAT('Files ',FileCount,'; volumes ',VolumeCount,
                  '; internal free ',CONVERT(varchar(32),InternalFreeGB),' GB; growth ',
                  COALESCE(CONVERT(varchar(32),AdditionalGrowthGB),'UNKNOWN'),
                  ' GB; total reserve ',COALESCE(CONVERT(varchar(32),EffectiveHeadroomGB),'UNKNOWN'),
                  ' GB. ',FilegroupAssessment,'. ',FilegroupRecommendation)
    FROM #FilegroupCapacity
    WHERE FilegroupAssessment NOT LIKE 'OK%';

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'WARNING','STORAGE POLICY',
           CONCAT(DatabaseName,N'.',COALESCE(FilegroupName,N'?')),
           CONCAT(PlannedStorageAction,': ',PlannedStorageReason,
                  ' (fixed volumes=',FixedVolumeCount,
                  ', extendable=',ExpandableVolumeCount,
                  ', policy extension GB=',COALESCE(CONVERT(varchar(32),PotentialVolumeExtensionGB),'UNKNOWN'),').')
    FROM #FilegroupCapacity
    WHERE PlannedStorageAction IN ('PROTECT FIXED VOLUME','VERIFY POLICY AND METADATA');

    SELECT '12F DATA FILE CAPACITY & EXPANSION ADVISORY' AS Section,*
    FROM #DataFileAdvisory
    WHERE FileSizeTB>=@DataFileReviewTB OR Assessment<>'OK'
    ORDER BY CASE WHEN Assessment LIKE 'CRITICAL%' THEN 0
                  WHEN Assessment LIKE 'WARNING%' THEN 1
                  WHEN Assessment LIKE 'UNKNOWN%' THEN 2 ELSE 3 END,
             FileHeadroomGB,FileSizeTB DESC,DatabaseName,LogicalFileName;

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT CASE WHEN Assessment LIKE 'CRITICAL%' THEN 'CRITICAL'
                WHEN Assessment LIKE 'WARNING%' OR Assessment LIKE 'UNKNOWN%' THEN 'WARNING'
                ELSE 'INFO' END,
           'DATA FILE CAPACITY',CONCAT(DatabaseName,N'.',LogicalFileName),
           CONCAT('FG ',COALESCE(FilegroupName,N'unknown'),
                  ' (',FilegroupFileCount,' file(s), inside free ',
                  COALESCE(CONVERT(varchar(32),FilegroupFreeInsidePct),'UNKNOWN'),
                  '%); allocated ',AllocatedMB,' MB; file inside free ',
                  COALESCE(CONVERT(varchar(32),FreeInsideMB),'UNKNOWN'),' MB (',
                  COALESCE(CONVERT(varchar(32),FreeInsidePct),'UNKNOWN'),' %); effective headroom ',
                  COALESCE(CONVERT(varchar(32),FileHeadroomGB),'UNKNOWN'),' GB; volume free ',
                  COALESCE(CONVERT(varchar(32),VolumeFreeGB),'UNKNOWN'),' GB. ',
                  Assessment,'. ',Recommendation)
    FROM #DataFileAdvisory
    WHERE FileSizeTB>=@DataFileReviewTB OR Assessment<>'OK';
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','DATA FILE CAPACITY',NULL,
        CONCAT('Data file advisory unavailable: ',ERROR_MESSAGE()));
END CATCH;

/* 12H. Linked Server configuration (passive inventory; no provider strings/passwords). */
CREATE TABLE #LSInventory
(
    ServerId int PRIMARY KEY, LinkedServer sysname NOT NULL,
    ProviderName nvarchar(128) NULL, DataSource nvarchar(4000) NULL,
    CatalogName sysname NULL, DataAccess bit NOT NULL, RpcOut bit NOT NULL,
    ConnectTimeout int NULL, QueryTimeout int NULL, ModifiedAt datetime NULL
);
BEGIN TRY
    INSERT #LSInventory
    SELECT server_id,name,provider,data_source,catalog,is_data_access_enabled,
           is_rpc_out_enabled,connect_timeout,query_timeout,modify_date
    FROM sys.servers WHERE is_linked=1;

    SELECT '12H LINKED_SERVER_CONFIGURATION' AS Section,
           @Now AS CapturedAt,@PolicyInstance AS InstanceName,
           CONVERT(sysname,SERVERPROPERTY('ComputerNamePhysicalNetBIOS')) AS ActiveNode,
           i.LinkedServer,i.ProviderName,i.DataSource,i.CatalogName,i.DataAccess,i.RpcOut,
           i.ConnectTimeout,i.QueryTimeout,i.ModifiedAt,
           l.local_principal_id AS LocalPrincipalId,
           CASE WHEN l.server_id IS NULL THEN NULL
                WHEN l.local_principal_id=0 THEN N'<ALL LOGINS>'
                ELSE COALESCE(p.name,N'<NOT VISIBLE>') END AS LocalLogin,
           l.uses_self_credential AS UsesSelfCredential,l.remote_name AS RemoteLogin,
           CASE WHEN l.server_id IS NULL THEN 'NO VISIBLE MAPPING'
                WHEN l.uses_self_credential=1 THEN 'CURRENT SECURITY CONTEXT'
                WHEN l.remote_name IS NULL THEN 'NO SECURITY CONTEXT'
                ELSE 'EXPLICIT REMOTE LOGIN' END AS MappingType,
           ORIGINAL_LOGIN() AS CollectorLogin,
           IS_SRVROLEMEMBER(N'sysadmin') AS CollectorIsSysadmin
    FROM #LSInventory i
    LEFT JOIN sys.linked_logins l ON l.server_id=i.ServerId
    LEFT JOIN sys.server_principals p ON p.principal_id=l.local_principal_id
    ORDER BY i.LinkedServer,l.local_principal_id;

    IF COALESCE(IS_SRVROLEMEMBER(N'sysadmin'),0)=0
        INSERT #Alerts VALUES ('INFO','LINKED SERVER',NULL,
            N'Linked server and login mapping metadata may be restricted by collector permissions.');

    INSERT #Alerts(Severity,Area,ObjectName,Details)
    SELECT 'INFO','LINKED SERVER',LinkedServer,
           'Legacy SQL Native Client provider; plan migration separately, not as automatic remediation.'
    FROM #LSInventory WHERE ProviderName LIKE N'SQLNCLI%';
END TRY
BEGIN CATCH
    INSERT #Alerts VALUES ('WARNING','LINKED SERVER',NULL,ERROR_MESSAGE());
END CATCH;

/* 12I. Inbound anonymous logon evidence, reusing existing ERRORLOG scan.
   These messages do not by themselves prove a Linked Server or Kerberos failure. */
SELECT DISTINCT '12I LINKED_SERVER_AUTH_EVENTS' AS Section,
       @PolicyInstance AS InstanceName,LogDate,ProcessInfo,[Text] AS Message
FROM #ErrorLogRaw
WHERE LogDate>=@Since AND LogDate<=@Now
  AND UPPER([Text]) LIKE N'%LOGIN FAILED%ANONYMOUS LOGON%'
ORDER BY LogDate DESC;
IF EXISTS (SELECT 1 FROM #ErrorLogRaw WHERE LogDate>=@Since AND LogDate<=@Now
           AND UPPER([Text]) LIKE N'%LOGIN FAILED%ANONYMOUS LOGON%')
    INSERT #Alerts VALUES ('WARNING','LINKED SERVER AUTH',NULL,
        'Inbound ANONYMOUS LOGON failures in available ERRORLOG window; correlate client IP and AD/Kerberos events. Source not proven.');

/* 12J. Optional connectivity: explicit allowlist, serial, one read-only OPENQUERY per target.
   Only SQL Server providers are supported. No server/linked-server settings changed.
   Local result capture can enlist a distributed transaction depending on provider/configuration.
   Provider timeouts are not a guaranteed wall-clock deadline; external cancellation required
   for a strict deadline. Run separately from unattended DHC if that is mandatory. */
CREATE TABLE #LSProbeResult
(
    LinkedServer sysname NOT NULL, ProbeStatus varchar(32) NOT NULL,
    StartedAt datetime2(3) NULL, DurationMs bigint NULL,
    RemoteServer nvarchar(128) NULL, RemoteOriginalLogin nvarchar(128) NULL,
    RemoteLogin nvarchar(128) NULL, RemoteAuthScheme nvarchar(40) NULL,
    ErrorNumber int NULL, ErrorSeverity int NULL, ErrorState int NULL,
    Details nvarchar(4000) NULL
);
CREATE TABLE #LSProbeRemote
(
    RemoteServer nvarchar(128), RemoteOriginalLogin nvarchar(128),
    RemoteLogin nvarchar(128), RemoteAuthScheme nvarchar(40)
);
IF @EnableLinkedServerConnectivity=0
    INSERT #LSProbeResult(LinkedServer,ProbeStatus,Details)
    VALUES(N'<ALL>','DISABLED',N'Active tests disabled by default.');
ELSE
BEGIN
    DECLARE @LSName sysname,@LSProvider nvarchar(128),@LSAccess bit,
            @LSConnect int,@LSQuery int,@LSStarted datetime2(3),@LSCommand nvarchar(max);
    DECLARE @LSDefaultConnect int,@LSDefaultQuery int;
    SELECT @LSDefaultConnect=CONVERT(int,value_in_use) FROM sys.configurations WHERE name='remote login timeout (s)';
    SELECT @LSDefaultQuery=CONVERT(int,value_in_use) FROM sys.configurations WHERE name='remote query timeout (s)';
    IF NOT EXISTS(SELECT 1 FROM #LSProbeAllowlist)
        INSERT #LSProbeResult(LinkedServer,ProbeStatus,Details)
        VALUES(N'<ALL>','SKIPPED',N'Explicit allowlist is empty.');
    DECLARE LSProbeCursor CURSOR LOCAL FAST_FORWARD FOR
        SELECT a.LinkedServer,i.ProviderName,i.DataAccess,
               COALESCE(NULLIF(i.ConnectTimeout,0),@LSDefaultConnect),
               COALESCE(NULLIF(i.QueryTimeout,0),@LSDefaultQuery)
        FROM #LSProbeAllowlist a LEFT JOIN #LSInventory i ON i.LinkedServer=a.LinkedServer
        ORDER BY a.LinkedServer;
    OPEN LSProbeCursor;
    FETCH NEXT FROM LSProbeCursor INTO @LSName,@LSProvider,@LSAccess,@LSConnect,@LSQuery;
    WHILE @@FETCH_STATUS=0
    BEGIN
        IF @LSAccess IS NULL OR @LSAccess=0 OR @LSProvider IS NULL
           OR (@LSProvider NOT LIKE N'SQLNCLI%' AND @LSProvider NOT IN(N'MSOLEDBSQL',N'MSOLEDBSQL19',N'SQLOLEDB'))
           OR @LSConnect IS NULL OR @LSQuery IS NULL
           OR @LSConnect NOT BETWEEN 1 AND @LinkedServerMaxConnectSeconds
           OR @LSQuery NOT BETWEEN 1 AND @LinkedServerMaxQuerySeconds
           OR @@TRANCOUNT<>0
            INSERT #LSProbeResult(LinkedServer,ProbeStatus,Details)
            VALUES(@LSName,'SKIPPED',CONCAT(N'Unavailable/unsupported target, disabled data access, open transaction or timeout outside policy. Effective connect/query seconds: ',@LSConnect,N'/',@LSQuery));
        ELSE
        BEGIN
            SET @LSStarted=SYSDATETIME();
            BEGIN TRY
                DELETE FROM #LSProbeRemote;
                SET @LSCommand=N'SELECT RemoteServer,RemoteOriginalLogin,RemoteLogin,RemoteAuthScheme FROM OPENQUERY('
                    +QUOTENAME(@LSName)+N', ''SELECT CONVERT(nvarchar(128),@@SERVERNAME) AS RemoteServer,
                    CONVERT(nvarchar(128),ORIGINAL_LOGIN()) AS RemoteOriginalLogin,
                    CONVERT(nvarchar(128),SUSER_SNAME()) AS RemoteLogin,
                    CONVERT(nvarchar(40),CONNECTIONPROPERTY(''''auth_scheme'''')) AS RemoteAuthScheme'');';
                -- INSERT EXEC is local; the remote statement is SELECT only.
                INSERT #LSProbeRemote EXEC sys.sp_executesql @LSCommand;
                INSERT #LSProbeResult(LinkedServer,ProbeStatus,StartedAt,DurationMs,RemoteServer,RemoteOriginalLogin,RemoteLogin,RemoteAuthScheme,Details)
                SELECT @LSName,'SUCCESS',@LSStarted,DATEDIFF_BIG(MILLISECOND,@LSStarted,SYSDATETIME()),
                       RemoteServer,RemoteOriginalLogin,RemoteLogin,RemoteAuthScheme,N'Observed under collector security context.'
                FROM #LSProbeRemote;
            END TRY
            BEGIN CATCH
                INSERT #LSProbeResult(LinkedServer,ProbeStatus,StartedAt,DurationMs,ErrorNumber,ErrorSeverity,ErrorState,Details)
                VALUES(@LSName,'FAILED',@LSStarted,DATEDIFF_BIG(MILLISECOND,@LSStarted,SYSDATETIME()),ERROR_NUMBER(),ERROR_SEVERITY(),ERROR_STATE(),ERROR_MESSAGE());
            END CATCH;
        END;
        FETCH NEXT FROM LSProbeCursor INTO @LSName,@LSProvider,@LSAccess,@LSConnect,@LSQuery;
    END;
    CLOSE LSProbeCursor;
    DEALLOCATE LSProbeCursor;
END;
SELECT '12J LINKED_SERVER_CONNECTIVITY' AS Section,@Now AS CapturedAt,
       @PolicyInstance AS InstanceName,ORIGINAL_LOGIN() AS CollectorLogin,
       SUSER_SNAME() AS CollectorCurrentLogin,
       CONVERT(nvarchar(40),CONNECTIONPROPERTY('auth_scheme')) AS CollectorAuthScheme,*
FROM #LSProbeResult ORDER BY LinkedServer;
INSERT #Alerts(Severity,Area,ObjectName,Details)
SELECT 'WARNING','LINKED SERVER',LinkedServer,
       LEFT(CONCAT(ProbeStatus,N'; error=',ErrorNumber,N'; ',Details),2000)
FROM #LSProbeResult WHERE ProbeStatus='FAILED';

/* 11. Actionable summary */
SELECT '13 SUMMARY' AS Section, Severity,Area,ObjectName,Details
FROM #Alerts
ORDER BY CASE Severity WHEN 'CRITICAL' THEN 1 WHEN 'WARNING' THEN 2 ELSE 3 END,
         Area,ObjectName,Id;

SELECT '14 COUNTS' AS Section,
       (SELECT COUNT(*) FROM #Alerts WHERE Severity='CRITICAL') AS CriticalAlerts,
       (SELECT COUNT(*) FROM #Alerts WHERE Severity='WARNING') AS WarningAlerts,
       (SELECT COUNT(*) FROM #Alerts WHERE Severity='INFO') AS InfoAlerts,
       @Since AS SinceTime,@Now AS UntilTime;

/* Notes:
 - Expected schedule detection is a best-effort approximation, not Agent internals.
   Agent downtime, schedule editing, daylight savings and overlapping jobs can
   produce false positives. Startup/idle and <60-second schedules excluded.
 - Growth between snapshots is NET change, not proof of an autogrowth event.
 - Autogrowth event history uses Default Trace; its rolling retention may be less than 24 hours.
 - No Extended Events session is deployed by this diagnostic script.
 - LOG oversizing and capacity analysis are read-only; potential shrink is an upper bound, not a guarantee.
 - DATA FILE advisory checks FILEPROPERTY SpaceUsed in each accessible database and filegroup metadata; unavailable measurements are UNKNOWN.
 - Filegroup 12G counts each volume only once WITHIN that filegroup; other filegroups/databases
   may compete for space on the same volume, so figures are upper-bound estimates, not guarantees.
 - v6 volume policy: configurable per SERVERPROPERTY('ServerName') AND drive letter;
   there are NO DEFAULT rules for other instances. Use #VolumePolicyCatalog.
   12G0 lists configured drives; unobserved volumes are not validated for ADD FILE.
   A missing rule is UNKNOWN, never interpreted as expandable or fixed.
   Planned volume extension is never included in current EffectiveHeadroomGB.
 - v4 RecommendedAction is chosen for the WHOLE filegroup; ADD FILE RECOMMENDED is
   conditional on verifying a suitable target volume separately (not discovered here).
 - Existing volume capacity may be claimed by other databases/filegroups; action flags
   do not prove storage is exclusively available to this database.
 - Filegroup thresholds use static GB; no 30/60/90-day prediction without measured growth history.
 - Effective headroom is a point-in-time per-file estimate and must NOT be summed across files on the same volume.
 - Log utilisation is a point-in-time value; the optional history tracks file size, not used-log peaks.
 - Disk trend uses last two runs; run daily at similar time for interpretation.
 - FCI comparison detects active-node changes between snapshots, not every failover.
 - Linked Server snapshots are emitted as result sets for CSV retention; existing hc history schema is unchanged.
 - Active probes may create remote sessions and audit entries; they never change linked-server configuration.
 - A history write is the only persistent data modification made by the daily script.
*/

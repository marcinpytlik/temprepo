/*
 SQLManiak | Linked Server diagnostics: SQL Server 2019 -> 2022
 Wersja 1.0 | Tylko diagnostyka, bez zmian konfiguracji.

 KOLEJNOSC (SSMS, zaznacz i wykonaj kazda sekcje osobno):
 A: SQL 2019 (zrodlo) oraz SQL 2022 (cel).
 B: SQL 2019 - ustaw nazwe niedzialajacego Linked Server.
 C: SQL 2022 - bezposrednio po B, sprawdz ERRORLOG.
 D: SQL 2022 - ustaw nazwe dzialajacego Linked Server do SQL 2019.
 E: Windows/PowerShell na aktywnym wezle SQL 2019 (instrukcja na koncu).
 Uruchamiaj jako administrator DBA, a test B powtorz jako rzeczywisty
 uzytkownik/aplikacja (jesli mozliwe), z tego samego miejsca co zwykle.
 Testy polaczen moga trwac do skonfigurowanego timeoutu i zapisac blad w logu.
 Nie udostepniaj publicznie nazw kont, hostow, adresow ani logow bez anonimizacji.
*/

-- ============================================================
-- A. OBA SERWERY: SQL 2019 oraz SQL 2022
-- ============================================================
USE master;
GO
SELECT N'A1 - Instance' AS Section, SYSDATETIMEOFFSET() AS CapturedAt,
    @@SERVERNAME AS ServerName,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductUpdateLevel') AS CU,
    SERVERPROPERTY('Edition') AS Edition,
    SERVERPROPERTY('IsClustered') AS IsClustered,
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS CurrentNode,
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS WindowsAuthOnly;

SELECT N'A2 - Linked servers' AS Section, name, product, provider,
    data_source, catalog, connect_timeout, query_timeout,
    is_data_access_enabled, is_rpc_out_enabled, is_remote_login_enabled,
    is_collation_compatible, uses_remote_collation, collation_name,
    lazy_schema_validation, is_remote_proc_transaction_promotion_enabled,
    modify_date
FROM sys.servers WHERE is_linked = 1 ORDER BY name;
-- provider_string celowo pominiety: moze zawierac dane poufne.

SELECT N'A3 - Login mappings' AS Section, s.name AS LinkedServer,
    CASE WHEN l.local_principal_id = 0 THEN N'<ALL LOGINS>'
         ELSE COALESCE(p.name, N'<NOT VISIBLE>') END AS LocalLogin,
    l.uses_self_credential, l.remote_name, l.modify_date
FROM sys.linked_logins AS l
JOIN sys.servers AS s ON s.server_id = l.server_id
LEFT JOIN sys.server_principals AS p ON p.principal_id = l.local_principal_id
ORDER BY s.name, l.local_principal_id;

PRINT 'A4 - Registered OLE DB providers (not DLL versions)';
BEGIN TRY
    EXEC master.dbo.sp_enum_oledb_providers;
END TRY BEGIN CATCH
    SELECT ERROR_NUMBER() AS ErrorNumber, ERROR_MESSAGE() AS ErrorMessage;
END CATCH;

SELECT N'A5 - Current client connection' AS Section,
    ORIGINAL_LOGIN() AS OriginalLogin, SUSER_SNAME() AS CurrentLogin,
    auth_scheme, net_transport, encrypt_option, client_net_address,
    local_net_address, local_tcp_port
FROM sys.dm_exec_connections WHERE session_id = @@SPID;

SELECT N'A6 - TCP listeners' AS Section, ip_address, port, type_desc, state_desc
FROM sys.dm_tcp_listener_states;

SELECT N'A7 - Service accounts' AS Section, servicename, service_account,
    status_desc, last_startup_time, is_clustered, cluster_nodename
FROM sys.dm_server_services;

SELECT N'A8 - Server timeouts' AS Section, name, value_in_use
FROM sys.configurations
WHERE name IN (N'remote login timeout (s)', N'remote query timeout (s)');
GO

-- ============================================================
-- B. TYLKO SQL 2019: niedzialajacy kierunek 2019 -> 2022
-- ============================================================
USE master;
GO
DECLARE @LinkedServer sysname = N'WPISZ_NAZWE_LINKED_SERVER_DO_2022';
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE is_linked = 1 AND name = @LinkedServer)
BEGIN
    PRINT 'STOP: ustaw poprawna nazwe Linked Server w sekcji B.';
    RETURN;
END;
DECLARE @Started datetimeoffset = SYSDATETIMEOFFSET();
SELECT N'B1 - Test start' AS Section, @Started AS StartedAt,
    @@SERVERNAME AS SourceServer, @LinkedServer AS LinkedServer,
    ORIGINAL_LOGIN() AS OriginalLogin, SUSER_SNAME() AS CurrentLogin;
BEGIN TRY
    EXEC master.dbo.sp_testlinkedserver @servername = @LinkedServer;
    SELECT N'B2 - PASS' AS Result;
END TRY BEGIN CATCH
    SELECT N'B2 - FAIL' AS Result, ERROR_NUMBER() AS ErrorNumber,
        ERROR_STATE() AS ErrorState, ERROR_MESSAGE() AS ErrorMessage;
    PRINT 'Skopiuj rowniez pelna zakladke Messages (komunikaty providera).';
END CATCH;
SELECT N'B3 - Test end' AS Section, SYSDATETIMEOFFSET() AS FinishedAt,
    DATEDIFF_BIG(MILLISECOND, @Started, SYSDATETIMEOFFSET()) AS DurationMs;
GO

-- ============================================================
-- C. TYLKO SQL 2022: cel, natychmiast po wykonaniu B
-- ============================================================
USE master;
GO
DECLARE @From datetime = DATEADD(MINUTE, -15, GETDATE());
DECLARE @To datetime = GETDATE();
SELECT N'C1 - Error log window' AS Section, @@SERVERNAME AS ServerName,
    @From AS FromLocal, @To AS ToLocal, SYSDATETIMEOFFSET() AS CapturedAt;
-- Oddzielne filtry: stan 18456 moze wystapic w osobnym wierszu.
PRINT 'C2 - Login failed';
EXEC master.dbo.xp_readerrorlog 0, 1, N'Login failed', NULL, @From, @To, N'desc';
PRINT 'C3 - Error 18456';
EXEC master.dbo.xp_readerrorlog 0, 1, N'18456', NULL, @From, @To, N'desc';
PRINT 'C4 - Handshake';
EXEC master.dbo.xp_readerrorlog 0, 1, N'handshake', NULL, @From, @To, N'desc';
PRINT 'C5 - SSPI';
EXEC master.dbo.xp_readerrorlog 0, 1, N'SSPI', NULL, @From, @To, N'desc';
PRINT 'C6 - TLS';
EXEC master.dbo.xp_readerrorlog 0, 1, N'TLS', NULL, @From, @To, N'desc';
PRINT 'C7 - Certificate';
EXEC master.dbo.xp_readerrorlog 0, 1, N'certificate', NULL, @From, @To, N'desc';
-- Brak wpisu NIE dowodzi, ze pakiety nie dotarly do serwera.
GO

-- ============================================================
-- D. TYLKO SQL 2022: kontrola dzialajacego kierunku 2022 -> 2019
-- ============================================================
USE master;
GO
DECLARE @LinkedServer sysname = N'WPISZ_NAZWE_LINKED_SERVER_DO_2019';
IF NOT EXISTS (SELECT 1 FROM sys.servers WHERE is_linked = 1 AND name = @LinkedServer)
BEGIN
    PRINT 'STOP: ustaw poprawna nazwe Linked Server w sekcji D.';
    RETURN;
END;
DECLARE @Started datetimeoffset = SYSDATETIMEOFFSET();
BEGIN TRY
    EXEC master.dbo.sp_testlinkedserver @servername = @LinkedServer;
    SELECT N'D1 - PASS' AS Result;
    DECLARE @RemoteQuery nvarchar(max) = N'SELECT @@SERVERNAME AS RemoteServer, ORIGINAL_LOGIN() AS OriginalLogin, SUSER_SNAME() AS CurrentLogin';
    DECLARE @SQL nvarchar(max) = N'SELECT * FROM OPENQUERY(' + QUOTENAME(@LinkedServer)
        + N', ''' + REPLACE(@RemoteQuery, N'''', N'''''') + N''');';
    EXEC sys.sp_executesql @SQL;
END TRY BEGIN CATCH
    SELECT N'D - FAIL' AS Result, ERROR_NUMBER() AS ErrorNumber,
        ERROR_STATE() AS ErrorState, ERROR_MESSAGE() AS ErrorMessage;
END CATCH;
SELECT N'D2 - Duration' AS Section, DATEDIFF_BIG(MILLISECOND, @Started, SYSDATETIMEOFFSET()) AS DurationMs;
GO

/* ============================================================
 E. POWERSHELL - NIE URUCHAMIAC JAKO T-SQL
 Na aktywnym wezle SQL 2019. Ustaw faktyczny FQDN/VNN i port z A6.

 $Target = 'SQL2022.domena.local'
 $Port = 1433
 Resolve-DnsName $Target
 Test-NetConnection -ComputerName $Target -Port $Port -InformationLevel Detailed

 Wersje zainstalowanych sterownikow (na obu aktywnych wezlach):
 Get-Item "$env:windir\System32\msoledbsql.dll", `
          "$env:windir\System32\msoledbsql19.dll", `
          "$env:windir\System32\sqlncli11.dll" -ErrorAction SilentlyContinue |
     Select-Object Name, @{N='FileVersion';E={$_.VersionInfo.FileVersion}}

 W FCI porownaj sterowniki rowniez na pozostalych wezlach, bez failoveru.

 F. DO ANALIZY PRZESLIJ: A z obu instancji, B (Results i Messages), C, D, E.
 Nie zmieniaj jeszcze providera, TLS, SPN, AllowInProcess ani mapowania loginow.
 Brak uprawnien do DMV/ERRORLOG: zapisz komunikat, nie nadawaj uprawnien na potrzeby testu.
 Skrypt nie ustala samodzielnie przyczyny; wyniki wymagaja korelacji.
 ============================================================ */

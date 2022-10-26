using System;

namespace SysadminsLV.PKI.Management.CertificateServices;

/// <summary>
/// Contains enumeration of CA database control settings.
/// </summary>
// from CertSrv.h
[Flags]
public enum CertSrvDbFlags {
    /// <summary>
    /// None.
    /// </summary>
    None                       = 0,
    /// <summary>
    /// The database is in read-only mode. Not used.
    /// </summary>
    ReadOnly                   = 0x001,  // ignored in registry
    /// <summary>
    /// Instructs CA to create a new database if one doesn't exist upon service start.
    /// </summary>
    CreateIfNeeded             = 0x002,
    /// <summary>
    /// 
    /// </summary>
    CircularLogging            = 0x004,
    /// <summary>
    /// Flush database cache two seconds after all new extent data was added to the database. By default,
    /// database flushes its cache every two seconds after each extent (up to 16K) was added. 
    /// </summary>
    LazyFlush = 0x008,
    /// <summary>
    /// Multiply max cache size by 100.
    /// </summary>
    MaxCacheSizeX100           = 0x010,
    /// <summary>
    /// Keep the track of last 60 DB checkpoints.
    /// </summary>
    CheckpointDepth60MB        = 0x020,
    /// <summary>
    /// N/A
    /// </summary>
    LogBuffersLarge            = 0x040,
    /// <summary>
    /// N/A
    /// </summary>
    LogBuffersHuge             = 0x080,
    /// <summary>
    /// Use log files of fixed 16MB size. Default is to use fixed 1MB log files.
    /// </summary>
    LogFileSize16MB            = 0x100,
    /// <summary>
    /// Use multi-thread transactions to update database.
    /// </summary>
    UseMultiThreadTransactions = 0x200,
    /// <summary>
    /// Not used.
    /// </summary>
    DisableSnapshotBackup      = 0x400, // ignored in registry
    /// <summary>
    /// Enables in-memory requests which are not persistent in CA database.
    /// </summary>
    EnableVolatileRequests     = 0x800 // enables the use of CCertDBMem
}
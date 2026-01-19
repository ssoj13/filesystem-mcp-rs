# Filesystem MCP - Architecture Diagrams

## Module Structure

```mermaid
graph TB
    subgraph "Entry Point"
        main[main.rs<br/>MCP Server + Tool Router]
    end
    
    subgraph "Core Modules"
        allowed[allowed.rs<br/>AllowedDirs]
        path[path.rs<br/>Path Resolution]
        fs_ops[fs_ops.rs<br/>Read/Write/List]
        edit[edit.rs<br/>Text Editing]
        diff[diff.rs<br/>Unified Diff]
    end
    
    subgraph "File Operations"
        search[search.rs<br/>Glob Search]
        grep[grep.rs<br/>Content Search (include/exclude)]
        binary[binary.rs<br/>Binary R/W]
        line_edit[line_edit.rs<br/>Line Editing]
        bulk_edit[bulk_edit.rs<br/>Bulk Edits]
    end
    
    subgraph "Analysis"
        hash[hash.rs<br/>File Hashing]
        compare[compare.rs<br/>File/Dir Compare]
        stats[stats.rs<br/>Statistics]
        duplicates[duplicates.rs<br/>Duplicate Finder]
    end
    
    subgraph "Formats"
        archive[archive.rs<br/>ZIP/TAR]
        json_reader[json_reader.rs<br/>JSON + Query]
        pdf_reader[pdf_reader.rs<br/>PDF Extract]
    end

    subgraph "Network"
        http_tools[http_tools.rs<br/>HTTP/HTTPS Tools]
        s3_tools[s3_tools.rs<br/>S3 Tools]
    end
    
    subgraph "Runtime"
        process[process.rs<br/>Command Execution]
        watch[watch.rs<br/>File Watch/Tail]
        logging[logging.rs<br/>Tracing]
        format[format.rs<br/>Schema Fix]
    end
    
    main --> allowed
    main --> path
    main --> fs_ops
    main --> edit
    main --> search
    main --> grep
    main --> binary
    main --> line_edit
    main --> bulk_edit
    main --> hash
    main --> compare
    main --> stats
    main --> duplicates
    main --> archive
    main --> json_reader
    main --> pdf_reader
    main --> http_tools
    main --> s3_tools
    main --> process
    main --> watch
```

## Data Flow: MCP Request → Response

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant Module
    participant FS as Filesystem
    
    Client->>Main: MCP Tool Call
    Main->>Main: Validate Args
    Main->>Main: resolve_path()
    Main->>Module: Call function
    Module->>FS: Read/Write
    FS-->>Module: Result
    Module-->>Main: Struct Result
    Main->>Main: Build JSON
    Main-->>Client: CallToolResult
```

## Data Flow: run_command (background)

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant Proc as process.rs
    participant PM as ProcessManager

    Client->>Main: run_command(background=true)
    Main->>Proc: run_command(...)
    Proc-->>Main: pid + immediate return
    Proc->>PM: register(pid, info)
    Main-->>Client: CallToolResult(pid)
```

## Dead Code Flow (to be cleaned)

```mermaid
graph LR
    subgraph "Unused Methods"
        A1[archive::extension]
        A2[grep::matches/counts/files/len/is_empty]
        A3[watch::name]
        A4[process::contains]
        A5[process::is_process_running]
        A6[search::parse_time]
    end
    
    subgraph "Unused Fields"
        B1[CompareResult::diff_samples]
        B2[CompareResult::file1_empty/file2_empty]
        B3[DirCompareResult::errors]
        B4[HashResult::algorithm]
        B5[FileHashResult::error]
        B6[JsonReadResult::total_keys/array_length]
        B7[PdfReadResult::char_count]
        B8[WatchResult::timed_out]
        B9[SearchResult::is_symlink/size/modified]
    end
    
    A1 -.->|DELETE| X((Removed))
    A2 -.->|DELETE| X
    A3 -.->|DELETE| X
    A4 -.->|DELETE| X
    A5 -.->|DELETE| X
    A6 -.->|DELETE| X
    
    B1 -.->|ADD TO JSON| Y((Exposed))
    B2 -.->|ADD TO JSON| Y
    B3 -.->|ADD TO JSON| Y
    B4 -.->|DELETE| X
    B5 -.->|ADD TO JSON| Y
    B6 -.->|ADD TO JSON| Y
    B7 -.->|ADD TO JSON| Y
    B8 -.->|ADD TO JSON| Y
    B9 -.->|DECISION| Z((TBD))
```

## Search Module Architecture (Incomplete Refactoring)

```mermaid
graph TB
    subgraph "Current State"
        API[MCP API: search_files]
        SP[search_paths<br/>Returns: Vec&lt;PathBuf&gt;]
        SFE[search_files_extended<br/>Returns: Vec&lt;SearchResult&gt;]
        SR[SearchResult struct<br/>path, is_file, is_dir,<br/>is_symlink, size, modified]
    end
    
    API -->|calls| SP
    SP -->|calls| SFE
    SFE -->|returns| SR
    SP -->|discards fields| PathBuf
    
    subgraph "Problem"
        LOST[Lost: is_file, is_dir,<br/>is_symlink, size, modified]
    end
    
    SR -.-> LOST
```

## Tool Categories

```mermaid
mindmap
  root((Filesystem MCP))
    Read
      read_text_file
      read_binary
      read_media_file
      read_multiple_files
      read_json
      read_pdf
    Write
      write_file
      write_binary
      create_directory
    Edit
      edit_file
      edit_lines
      bulk_edits
      extract_lines
      extract_symbols
      extract_binary
      patch_binary
    Search
      search_files
      grep_files
    Info
      get_file_info
      list_directory
      list_directory_with_sizes
      directory_tree
      file_stats
      list_allowed_directories
    Compare
      file_hash
      file_hash_multiple
      compare_files
      compare_directories
      find_duplicates
    Archive
      archive_extract
      archive_create
    Watch
      watch_file
      tail_file
    Process
      run_command
      kill_process
      list_processes
      search_processes
    Manage
      move_file
      copy_file
      delete_path
```

## File Watch Data Flow

```mermaid
stateDiagram-v2
    [*] --> Watching: watch_file()
    Watching --> Changed: File modified
    Watching --> Timeout: timeout_ms elapsed
    Changed --> [*]: Return event details
    Timeout --> [*]: Return timed_out=true
    
    note right of Changed
        Returns: changed=true,
        event, new_size, elapsed_ms
        Missing: timed_out flag!
    end note
```

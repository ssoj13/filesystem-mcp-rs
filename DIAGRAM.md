# Filesystem MCP — Architecture Diagrams

Living architecture overview. Tool names match the MCP surface in `src/main.rs`.

## Module Structure

```mermaid
graph TB
    subgraph Entry["Entry Point"]
        main["main.rs — MCP Server + Tool Router"]
    end

    subgraph Core["Core Modules"]
        allowed["allowed.rs — AllowedDirs"]
        path["path.rs — Path Resolution"]
        content_plane["content_plane.rs — ContentRef / blobs"]
        fs_ops["fs_ops.rs — Read/Write/List"]
        edit["edit.rs — Text Editing"]
        diff["diff.rs — Unified Diff"]
        serde["serde.rs — FlexBool / FlexUsize"]
        schema["schema.rs — JSON Schema"]
        glob["glob.rs — Pattern Matching"]
        format["format.rs — Output Formatting"]
        logging["logging.rs — Tracing"]
    end

    subgraph FileOps["File Operations"]
        search["search.rs — Glob Search"]
        grep["grep.rs / fast_grep.rs — Content Search"]
        binary["binary.rs — Binary R/W"]
        line_edit["line_edit.rs — Line Editing"]
        bulk_edit["bulk_edit.rs — Bulk Edits"]
        watch["watch.rs — File Watch/Tail"]
    end

    subgraph Analysis["Analysis"]
        hash["hash.rs — File Hashing"]
        compare["compare.rs — File/Dir Compare"]
        stats["stats.rs — Statistics"]
        duplicates["duplicates.rs — Duplicate Finder"]
    end

    subgraph Formats["Formats"]
        archive["archive.rs — ZIP/TAR"]
        json_reader["json_reader.rs — JSON + Query"]
        pdf_reader["pdf_reader.rs — PDF Extract"]
        xlsx["xlsx.rs — Excel"]
        docx["docx.rs — Word"]
        media["media.rs — Media Files"]
    end

    subgraph Network["Network optional features"]
        http_tools["http_tools.rs — HTTP/HTTPS"]
        s3_tools["s3_tools.rs — S3"]
        screenshot["screenshot.rs — Capture"]
    end

    subgraph Runtime["Runtime"]
        process["process.rs — Command Execution"]
        memory_v2["memory_v2/ — Scoped Memory + ACL"]
        llm["llm/ — Multi-provider LLM"]
        wave2["wave2/ — System Utilities"]
        thinking["thinking/ — Sequential Thinking"]
        mcp_setup["mcp_setup/ — Client Install Matrix"]
    end

    main --> allowed
    main --> path
    main --> content_plane
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
    main --> xlsx
    main --> docx
    main --> http_tools
    main --> s3_tools
    main --> screenshot
    main --> process
    main --> watch
    main --> memory_v2
    main --> llm
    main --> wave2
    main --> thinking
```

## Module Dependency Graph

```mermaid
graph TD
    MAIN["main.rs — FileSystemServer"] --> CORE["core/"]
    MAIN --> TOOLS["tools/"]
    MAIN --> SETUP["mcp_setup/ + setup.rs"]

    CORE --> ALLOWED["allowed.rs"]
    CORE --> FORMAT["format.rs"]
    CORE --> GLOB["glob.rs"]
    CORE --> LOGGING["logging.rs"]
    CORE --> PATH["path.rs"]
    CORE --> SCHEMA["schema.rs"]
    CORE --> SERDE["serde.rs"]

    TOOLS --> MEM["memory_v2/"]
    TOOLS --> LLM["llm/"]
    TOOLS --> WAVE["wave2/"]
    TOOLS --> THINK["thinking/"]
    TOOLS --> PROC["process.rs"]
    TOOLS --> WATCH["watch.rs"]
    TOOLS --> FILETOOLS["grep / search / edit / line_edit / bulk_edit"]
    TOOLS --> HASH["hash.rs"]
    TOOLS --> IO["archive / binary / compare / diff"]
    TOOLS --> READERS["pdf / json / xlsx / docx / media"]
    TOOLS --> NET["http_tools / s3_tools"]
    TOOLS --> SCREEN["screenshot.rs"]

    HASH --> MURMUR["murmur3.rs"]
    HASH --> SPOOKY["spooky.rs"]

    MEM --> SQLITE[("SQLite via r2d2")]
    LLM --> PROVIDERS["providers: openai / gemini / cerebras"]
    NET -.->|"feature: http-tools"| REQWEST["reqwest"]
    NET -.->|"feature: s3-tools"| AWS["aws-sdk-s3"]
    SCREEN -.->|"feature: screenshot-tools"| XCAP["xcap + image"]
```

## Tool Categories

Tool names as registered on the MCP server (from `src/main.rs`). Optional feature gates noted where relevant.

```mermaid
mindmap
  root((Filesystem MCP))
    Read
      read_text_file
      read_media_file
      read_multiple_files
      read_json
      read_pdf
      read_binary
      xlsx_info
      xlsx_sheets
      xlsx_read
      docx_info
      docx_read
    Write
      write_file
      write_binary
      blob_begin
      blob_append
      blob_finalize
      blob_stat
      create_directory
      file_touch
    Edit
      edit_file
      edit_lines
      bulk_edits
      extract_lines
      extract_symbols
      extract_binary
      patch_binary
      file_diff
    Search
      search_files
      grep_files
      grep_context
    Info
      get_file_info
      list_directory
      list_directory_with_sizes
      directory_tree
      file_stats
      list_allowed_directories
      disk_usage
      sys_info
      which
    Hash_Compare
      file_hash
      file_hash_multiple
      compare_files
      compare_directories
      find_duplicates
    Archive
      extract_archive
      create_archive
    Watch
      watch_file
      tail_file
    Process
      run_command
      kill_process
      list_processes
      search_processes
      proc_tree
      proc_env
      proc_files
    Network_wave2
      port_users
      net_connections
      port_available
    Manage
      move_file
      copy_file
      delete_path
      clipboard_read
      clipboard_write
      env_get
      env_set
      env_remove
      env_list
    HTTP_feature
      http_request
      http_request_batch
      http_download
      http_download_batch
    S3_feature
      s3_list_buckets
      s3_list
      s3_stat
      s3_get
      s3_put
      s3_delete
      s3_copy
      s3_presign
      s3_get_batch
      s3_put_batch
      s3_delete_batch
      s3_copy_batch
    Screenshot_feature
      screenshot_list_monitors
      screenshot_list_windows
      screenshot_capture_screen
      screenshot_capture_window
      screenshot_capture_region
      screenshot_copy_to_clipboard
    Memory_v2
      mem_put
      mem_update
      mem_link
      mem_search
      mem_get
      mem_get_summary
    AI_LLM
      ai_messages
      ai_messages_gemini
      ai_messages_openai
      ai_messages_cerebras
      ai_count_tokens
      ai_count_tokens_gemini
      ai_count_tokens_openai
      ai_count_tokens_cerebras
    Thinking
      seq_think
```

## Tool Request Pipeline

```mermaid
flowchart LR
    REQ["MCP Request"] --> DESER["Deserialize args<br/>FlexBool / FlexUsize"]
    DESER --> RESOLVE["self.resolve<br/>path validation"]
    RESOLVE --> ALLOWED{"Path in allowlist?"}
    ALLOWED -->|No| ERR["McpError"]
    ALLOWED -->|Yes| EXEC["Execute tool logic"]
    EXEC --> RESULT{"Success?"}
    RESULT -->|Yes| OK["CallToolResult<br/>text + structured_content"]
    RESULT -->|No| WRAP["internal_err wrapping"]
    WRAP --> ERR
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
    Main->>Main: resolve_path
    Main->>Module: Call function
    Module->>FS: Read/Write
    FS-->>Module: Result
    Module-->>Main: Struct Result
    Main->>Main: Build JSON
    Main-->>Client: CallToolResult
```

## Data Flow: run_command background + streamed logs

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant Proc as process.rs
    participant PM as ProcessManager

    Client->>Main: run_command mode=detached
    Main->>Proc: run_command
    Proc-->>Main: pid + immediate return
    Proc->>PM: register pid
    Main-->>Client: CallToolResult with pid and log paths
    Client->>Main: tail_file on stdoutFile or stderrFile
    Main-->>Client: incremental log chunks
```

## Data Flow: http_download

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant HTTP as http_tools
    participant FS as Filesystem

    Client->>Main: http_download url path
    Main->>HTTP: http_request
    HTTP-->>Main: HttpResponse status body
    alt status >= 400
        Main-->>Client: error with status
    else status OK
        Main->>FS: write body
        Main-->>Client: CallToolResult ok=true
    end
```

## HTTP Batch Status Handling

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant HTTP as http_tools

    Client->>Main: http_request_batch
    Main->>HTTP: http_request_batch
    HTTP-->>Main: HttpBatchResult with per-item status
    Main-->>Client: results[].ok false plus status/error
```

## Search Module API

```mermaid
graph TB
    API["search_files args"]
    SFE["search_files_extended filters"]
    API --> SFE
    API --> M["modifiedAfter / modifiedBefore"]
    SFE --> M
```

## Watch File: Missing Target Path

```mermaid
flowchart TB
    Call["watch_file path"] --> Check{"path is directory?"}
    Check -- true --> Watch["watch target dir"]
    Check -- false --> Parent["watch parent dir"]
    Parent --> Create["create events observed"]
```

## File Watch Data Flow

```mermaid
stateDiagram-v2
    [*] --> Watching: watch_file
    Watching --> Changed: File modified
    Watching --> Timeout: timeout_ms elapsed
    Changed --> [*]: Return event details
    Timeout --> [*]: Return timed_out=true
```

## LLM Integration Architecture

```mermaid
graph TB
    subgraph FileSystemServer["FileSystemServer"]
        FS["FileSystemServer"]
        FS_ROUTER["tool_router: filesystem tools"]
        LLM_EMBED["llm_server: Option LlmMcpServer"]
    end

    subgraph LlmMcpServer["LlmMcpServer"]
        LLM["LlmMcpServer"]
        LLM_ROUTER["ai_messages / ai_count_tokens"]
        STATE["AppState"]
        CONFIG["Config"]
        MODEL_MGR["ModelManager"]
    end

    subgraph Providers["Providers"]
        GEMINI["gemini.rs"]
        CEREBRAS["cerebras.rs"]
        OPENAI["openai.rs"]
    end

    FS --> LLM_EMBED
    LLM_EMBED --> LLM
    LLM --> LLM_ROUTER
    LLM --> STATE
    STATE --> CONFIG
    STATE --> MODEL_MGR
    LLM_ROUTER --> GEMINI
    LLM_ROUTER --> CEREBRAS
    LLM_ROUTER --> OPENAI
```

## Memory V2 Data Flow

```mermaid
sequenceDiagram
    participant Client as MCP Client
    participant Main as main.rs handler
    participant Store as SqliteMemoryStore
    participant DB as Database sync
    participant SQLite as SQLite DB

    Client->>Main: mem_put / mem_search / mem_get
    Main->>Main: Parse args workspaceId actorId item
    Main->>Store: store.put PutRequest async
    Store->>DB: spawn_blocking db.put
    DB->>DB: validate + build SQL
    DB->>SQLite: parameterized INSERT/SELECT
    SQLite-->>DB: Result
    DB->>DB: can_read_item / matches_filters
    DB-->>Store: Result Response
    Store-->>Main: Result Response
    Main-->>Client: CallToolResult JSON
```

## Access Control Flow

```mermaid
flowchart TD
    REQ["Incoming request"] --> MODE{"access_mode?"}

    MODE -->|AllowAll| ALLOW["Allow"]
    MODE -->|EnforcePrivateOnly| EPO{"item.visibility == Private?"}
    MODE -->|EnforceVisibility| CONTROL{"has_item_control?"}

    EPO -->|No not private| ALLOW
    EPO -->|Yes private| CTRL1{"has_item_control?"}
    CTRL1 -->|Yes| ALLOW
    CTRL1 -->|No| DENY["Deny"]

    CONTROL -->|Yes| ALLOW
    CONTROL -->|No| VIS{"Check visibility vs scope match"}
    VIS -->|Private| DENY
    VIS -->|Session| SESS{"scope.session_id matches?"}
    VIS -->|Topic| TOPIC{"scope.topic_id matches?"}
    VIS -->|Workspace| WS{"scope.workspace_id matches?"}
    VIS -->|App| APP{"scope.app_id matches?"}
    VIS -->|Tenant| TENANT{"scope.tenant_id matches?"}
    VIS -->|PublicRead| ALLOW

    SESS -->|Yes| ALLOW
    SESS -->|No| DENY
    TOPIC -->|Yes| ALLOW
    TOPIC -->|No| DENY
    WS -->|Yes| ALLOW
    WS -->|No| DENY
    APP -->|Yes| ALLOW
    APP -->|No| DENY
    TENANT -->|Yes| ALLOW
    TENANT -->|No| DENY
```

## Edit Tools: Nested Args Deserialization

`edits` accepts an array of objects, a JSON string of an array, or an array of JSON strings — via `core::serde::vec_or_string`.

```mermaid
sequenceDiagram
    participant Client
    participant Main as main.rs
    participant Serde as vec_or_string
    participant EditOp as EditOperation / LineEditInstruction

    Client->>Main: edit_file / edit_lines / bulk_edits
    Main->>Serde: deserialize edits
    alt array of objects
        Serde-->>Main: Vec EditOperation
    else JSON string of array
        Serde-->>Main: Vec EditOperation
    else array of JSON strings
        Serde-->>EditOp: Deserialize each string
        EditOp-->>Main: EditOperation
    end
```

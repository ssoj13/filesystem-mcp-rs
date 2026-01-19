use std::fs::File;
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::{Path, PathBuf};

use anyhow::{Result, Context, bail};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

/// Supported archive formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
}

impl ArchiveFormat {
    /// Detect format from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_string_lossy().to_lowercase();
        
        if name.ends_with(".zip") {
            Some(Self::Zip)
        } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Some(Self::TarGz)
        } else if name.ends_with(".tar") {
            Some(Self::Tar)
        } else {
            None
        }
    }
    
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "zip" => Ok(Self::Zip),
            "tar" => Ok(Self::Tar),
            "tar.gz" | "tgz" | "targz" => Ok(Self::TarGz),
            _ => bail!("Unknown archive format '{}'. Supported: zip, tar, tar.gz", s),
        }
    }
}

/// Result of archive extraction
#[derive(Debug, Clone)]
pub struct ExtractResult {
    /// Number of files extracted
    pub files_extracted: usize,
    /// Number of directories created
    pub dirs_created: usize,
    /// List of extracted file paths (relative)
    pub files: Vec<String>,
    /// Total bytes extracted
    pub total_bytes: u64,
}

/// Result of archive creation
#[derive(Debug, Clone)]
pub struct CreateResult {
    /// Number of files added
    pub files_added: usize,
    /// Archive file size
    pub archive_size: u64,
    /// Archive path
    pub archive_path: String,
}

/// Extract archive to destination directory
pub async fn extract_archive(
    archive_path: &Path,
    destination: &Path,
    format: Option<ArchiveFormat>,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    let archive_path = archive_path.to_path_buf();
    let destination = destination.to_path_buf();
    let format = format.or_else(|| ArchiveFormat::from_path(&archive_path))
        .ok_or_else(|| anyhow::anyhow!("Cannot detect archive format from extension"))?;
    let files_filter = files_filter.map(|f| f.to_vec());
    
    // Run sync extraction in blocking task
    tokio::task::spawn_blocking(move || {
        extract_archive_sync(&archive_path, &destination, format, files_filter.as_deref())
    }).await?
}

fn extract_archive_sync(
    archive_path: &Path,
    destination: &Path,
    format: ArchiveFormat,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    // Create destination if needed
    std::fs::create_dir_all(destination)
        .with_context(|| format!("Cannot create destination: {}", destination.display()))?;
    
    match format {
        ArchiveFormat::Zip => extract_zip(archive_path, destination, files_filter),
        ArchiveFormat::Tar => extract_tar(archive_path, destination, files_filter),
        ArchiveFormat::TarGz => extract_tar_gz(archive_path, destination, files_filter),
    }
}

fn extract_zip(
    archive_path: &Path,
    destination: &Path,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    let file = File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;
    
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| "Invalid ZIP archive")?;
    
    let mut files_extracted = 0;
    let mut dirs_created = 0;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        let name = entry.name().to_string();
        
        // Apply filter if specified
        if let Some(filter) = files_filter {
            if !filter.iter().any(|f| name.starts_with(f) || name == *f) {
                continue;
            }
        }
        
        let out_path = destination.join(&name);
        
        // Prevent path traversal
        if !out_path.starts_with(destination) {
            continue;
        }
        
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)?;
            dirs_created += 1;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            let mut outfile = File::create(&out_path)?;
            let bytes = std::io::copy(&mut entry, &mut outfile)?;
            total_bytes += bytes;
            files_extracted += 1;
            files.push(name);
        }
    }
    
    Ok(ExtractResult {
        files_extracted,
        dirs_created,
        files,
        total_bytes,
    })
}

fn extract_tar(
    archive_path: &Path,
    destination: &Path,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    let file = File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;
    
    extract_tar_from_reader(BufReader::new(file), destination, files_filter)
}

fn extract_tar_gz(
    archive_path: &Path,
    destination: &Path,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    let file = File::open(archive_path)
        .with_context(|| format!("Cannot open archive: {}", archive_path.display()))?;
    
    let gz = GzDecoder::new(BufReader::new(file));
    extract_tar_from_reader(gz, destination, files_filter)
}

fn extract_tar_from_reader<R: Read>(
    reader: R,
    destination: &Path,
    files_filter: Option<&[String]>,
) -> Result<ExtractResult> {
    let mut archive = tar::Archive::new(reader);
    
    let mut files_extracted = 0;
    let mut dirs_created = 0;
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let name = path.to_string_lossy().to_string();
        
        // Apply filter if specified
        if let Some(filter) = files_filter {
            if !filter.iter().any(|f| name.starts_with(f) || name == *f) {
                continue;
            }
        }
        
        let out_path = destination.join(&path);
        
        // Prevent path traversal
        if !out_path.starts_with(destination) {
            continue;
        }
        
        if entry.header().entry_type().is_dir() {
            std::fs::create_dir_all(&out_path)?;
            dirs_created += 1;
        } else if entry.header().entry_type().is_file() {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            
            let size = entry.size();
            entry.unpack(&out_path)?;
            total_bytes += size;
            files_extracted += 1;
            files.push(name);
        }
    }
    
    Ok(ExtractResult {
        files_extracted,
        dirs_created,
        files,
        total_bytes,
    })
}

/// Create archive from files/directories
pub async fn create_archive(
    paths: &[PathBuf],
    destination: &Path,
    format: Option<ArchiveFormat>,
) -> Result<CreateResult> {
    let paths = paths.to_vec();
    let destination = destination.to_path_buf();
    let format = format.or_else(|| ArchiveFormat::from_path(&destination))
        .unwrap_or(ArchiveFormat::Zip);
    
    tokio::task::spawn_blocking(move || {
        create_archive_sync(&paths, &destination, format)
    }).await?
}

fn create_archive_sync(
    paths: &[PathBuf],
    destination: &Path,
    format: ArchiveFormat,
) -> Result<CreateResult> {
    // Create parent dirs
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    match format {
        ArchiveFormat::Zip => create_zip(paths, destination),
        ArchiveFormat::Tar => create_tar(paths, destination),
        ArchiveFormat::TarGz => create_tar_gz(paths, destination),
    }
}

fn create_zip(paths: &[PathBuf], destination: &Path) -> Result<CreateResult> {
    let file = File::create(destination)
        .with_context(|| format!("Cannot create archive: {}", destination.display()))?;
    
    let mut zip = zip::ZipWriter::new(BufWriter::new(file));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    
    let mut files_added = 0;
    
    for path in paths {
        if path.is_file() {
            let name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            
            zip.start_file(&name, options)?;
            let mut f = File::open(path)?;
            std::io::copy(&mut f, &mut zip)?;
            files_added += 1;
        } else if path.is_dir() {
            add_dir_to_zip(&mut zip, path, path, options, &mut files_added)?;
        }
    }
    
    zip.finish()?;
    
    let archive_size = std::fs::metadata(destination)?.len();
    
    Ok(CreateResult {
        files_added,
        archive_size,
        archive_path: destination.display().to_string(),
    })
}

fn add_dir_to_zip<W: Write + std::io::Seek>(
    zip: &mut zip::ZipWriter<W>,
    base: &Path,
    current: &Path,
    options: zip::write::SimpleFileOptions,
    files_added: &mut usize,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(base)?;
        let name = rel_path.to_string_lossy().replace('\\', "/");
        
        if path.is_file() {
            zip.start_file(&name, options)?;
            let mut f = File::open(&path)?;
            std::io::copy(&mut f, zip)?;
            *files_added += 1;
        } else if path.is_dir() {
            zip.add_directory(&format!("{}/", name), options)?;
            add_dir_to_zip(zip, base, &path, options, files_added)?;
        }
    }
    
    Ok(())
}

fn create_tar(paths: &[PathBuf], destination: &Path) -> Result<CreateResult> {
    let file = File::create(destination)
        .with_context(|| format!("Cannot create archive: {}", destination.display()))?;
    
    create_tar_to_writer(paths, BufWriter::new(file), destination)
}

fn create_tar_gz(paths: &[PathBuf], destination: &Path) -> Result<CreateResult> {
    let file = File::create(destination)
        .with_context(|| format!("Cannot create archive: {}", destination.display()))?;
    
    let encoder = GzEncoder::new(BufWriter::new(file), Compression::default());
    create_tar_to_writer(paths, encoder, destination)
}

fn create_tar_to_writer<W: Write>(
    paths: &[PathBuf],
    writer: W,
    destination: &Path,
) -> Result<CreateResult> {
    let mut tar = tar::Builder::new(writer);
    let mut files_added = 0;
    
    for path in paths {
        if path.is_file() {
            let name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            
            tar.append_path_with_name(path, &name)?;
            files_added += 1;
        } else if path.is_dir() {
            add_dir_to_tar(&mut tar, path, path, &mut files_added)?;
        }
    }
    
    tar.finish()?;
    drop(tar);
    
    let archive_size = std::fs::metadata(destination)?.len();
    
    Ok(CreateResult {
        files_added,
        archive_size,
        archive_path: destination.display().to_string(),
    })
}

fn add_dir_to_tar<W: Write>(
    tar: &mut tar::Builder<W>,
    base: &Path,
    current: &Path,
    files_added: &mut usize,
) -> Result<()> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let rel_path = path.strip_prefix(base)?;
        
        if path.is_file() {
            tar.append_path_with_name(&path, rel_path)?;
            *files_added += 1;
        } else if path.is_dir() {
            add_dir_to_tar(tar, base, &path, files_added)?;
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;

    #[test]
    fn test_format_detection() {
        assert_eq!(ArchiveFormat::from_path(Path::new("test.zip")), Some(ArchiveFormat::Zip));
        assert_eq!(ArchiveFormat::from_path(Path::new("test.tar")), Some(ArchiveFormat::Tar));
        assert_eq!(ArchiveFormat::from_path(Path::new("test.tar.gz")), Some(ArchiveFormat::TarGz));
        assert_eq!(ArchiveFormat::from_path(Path::new("test.tgz")), Some(ArchiveFormat::TarGz));
        assert_eq!(ArchiveFormat::from_path(Path::new("test.txt")), None);
    }

    #[test]
    fn test_format_from_str() {
        assert!(matches!(ArchiveFormat::from_str("zip").unwrap(), ArchiveFormat::Zip));
        assert!(matches!(ArchiveFormat::from_str("TAR").unwrap(), ArchiveFormat::Tar));
        assert!(matches!(ArchiveFormat::from_str("tar.gz").unwrap(), ArchiveFormat::TarGz));
        assert!(ArchiveFormat::from_str("rar").is_err());
    }

    #[tokio::test]
    async fn test_create_and_extract_zip() {
        let dir = tempdir().unwrap();
        
        // Create test files
        let src_dir = dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("file1.txt"), "content1").unwrap();
        fs::write(src_dir.join("file2.txt"), "content2").unwrap();
        
        // Create archive
        let archive_path = dir.path().join("test.zip");
        let result = create_archive(
            &[src_dir.clone()],
            &archive_path,
            Some(ArchiveFormat::Zip),
        ).await.unwrap();
        
        assert_eq!(result.files_added, 2);
        assert!(archive_path.exists());
        
        // Extract archive
        let extract_dir = dir.path().join("extracted");
        let result = extract_archive(
            &archive_path,
            &extract_dir,
            None,
            None,
        ).await.unwrap();
        
        assert_eq!(result.files_extracted, 2);
        assert!(extract_dir.join("file1.txt").exists());
        assert!(extract_dir.join("file2.txt").exists());
    }

    #[tokio::test]
    async fn test_create_and_extract_tar_gz() {
        let dir = tempdir().unwrap();
        
        // Create test file
        let src_file = dir.path().join("test.txt");
        fs::write(&src_file, "hello world").unwrap();
        
        // Create archive
        let archive_path = dir.path().join("test.tar.gz");
        let result = create_archive(
            &[src_file],
            &archive_path,
            Some(ArchiveFormat::TarGz),
        ).await.unwrap();
        
        assert_eq!(result.files_added, 1);
        
        // Extract archive
        let extract_dir = dir.path().join("extracted");
        let result = extract_archive(
            &archive_path,
            &extract_dir,
            None,
            None,
        ).await.unwrap();
        
        assert_eq!(result.files_extracted, 1);
        assert!(extract_dir.join("test.txt").exists());
        
        let content = fs::read_to_string(extract_dir.join("test.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn test_extract_with_filter() {
        let dir = tempdir().unwrap();
        
        // Create zip with multiple files
        let src_dir = dir.path().join("src");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("include.txt"), "yes").unwrap();
        fs::write(src_dir.join("exclude.txt"), "no").unwrap();
        
        let archive_path = dir.path().join("test.zip");
        create_archive(&[src_dir], &archive_path, Some(ArchiveFormat::Zip)).await.unwrap();
        
        // Extract only specific file
        let extract_dir = dir.path().join("extracted");
        let result = extract_archive(
            &archive_path,
            &extract_dir,
            None,
            Some(&["include.txt".to_string()]),
        ).await.unwrap();
        
        assert_eq!(result.files_extracted, 1);
        assert!(extract_dir.join("include.txt").exists());
        assert!(!extract_dir.join("exclude.txt").exists());
    }
}

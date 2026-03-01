use portable_atomic::{AtomicU64, Ordering};
use rustc_hash::FxHashSet;
use std::{
    cmp,
    collections::VecDeque,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tar_core::parse::{Limits, ParseError, ParseEvent, Parser};
use tar_core::SparseEntry as CoreSparseEntry;
use tokio::{
    fs,
    io::{self, AsyncRead as Read, AsyncReadExt},
    sync::Mutex,
};
use tokio_stream::*;

use crate::{
    entry::{EntryFields, EntryIo},
    error::TarError,
    header::BLOCK_SIZE,
    other, Entry, Header, PaxExtensions,
};

/// A top-level representation of an archive file.
///
/// This archive can have an entry added to it and it can be iterated over.
#[derive(Debug)]
pub struct Archive<R: Read + Unpin> {
    inner: Arc<ArchiveInner<R>>,
}

impl<R: Read + Unpin> Clone for Archive<R> {
    fn clone(&self) -> Self {
        Archive {
            inner: self.inner.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ArchiveInner<R> {
    pos: AtomicU64,
    unpack_xattrs: bool,
    preserve_permissions: bool,
    preserve_mtime: bool,
    allow_external_symlinks: bool,
    overwrite: bool,
    ignore_zeros: bool,
    obj: Mutex<R>,
}

/// Configure the archive.
pub struct ArchiveBuilder<R: Read + Unpin> {
    obj: R,
    unpack_xattrs: bool,
    preserve_permissions: bool,
    preserve_mtime: bool,
    allow_external_symlinks: bool,
    overwrite: bool,
    ignore_zeros: bool,
}

impl<R: Read + Unpin> ArchiveBuilder<R> {
    /// Create a new builder.
    pub fn new(obj: R) -> Self {
        ArchiveBuilder {
            unpack_xattrs: false,
            preserve_permissions: false,
            preserve_mtime: true,
            allow_external_symlinks: true,
            overwrite: true,
            ignore_zeros: false,
            obj,
        }
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are preserved
    /// when unpacking this archive.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix using xattr support. This may eventually be implemented for
    /// Windows, however, if other archive implementations are found which do
    /// this as well.
    pub fn set_unpack_xattrs(mut self, unpack_xattrs: bool) -> Self {
        self.unpack_xattrs = unpack_xattrs;
        self
    }

    /// Indicate whether the permissions on files and directories are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix.
    pub fn set_preserve_permissions(mut self, preserve: bool) -> Self {
        self.preserve_permissions = preserve;
        self
    }

    /// Indicate whether files and symlinks should be overwritten on extraction.
    pub fn set_overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Indicate whether access time information is preserved when unpacking
    /// this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(mut self, preserve: bool) -> Self {
        self.preserve_mtime = preserve;
        self
    }

    /// Ignore zeroed headers, which would otherwise indicate to the archive that it has no more
    /// entries.
    ///
    /// This can be used in case multiple tar archives have been concatenated together.
    pub fn set_ignore_zeros(mut self, ignore_zeros: bool) -> Self {
        self.ignore_zeros = ignore_zeros;
        self
    }

    /// Indicate whether to deny symlinks that point outside the destination
    /// directory when unpacking this entry. (Writing to locations outside the
    /// destination directory is _always_ forbidden.)
    ///
    /// This flag is enabled by default.
    pub fn set_allow_external_symlinks(mut self, allow_external_symlinks: bool) -> Self {
        self.allow_external_symlinks = allow_external_symlinks;
        self
    }

    /// Construct the archive, ready to accept inputs.
    pub fn build(self) -> Archive<R> {
        let Self {
            unpack_xattrs,
            preserve_permissions,
            preserve_mtime,
            allow_external_symlinks,
            overwrite,
            ignore_zeros,
            obj,
        } = self;

        Archive {
            inner: Arc::new(ArchiveInner {
                unpack_xattrs,
                preserve_permissions,
                preserve_mtime,
                allow_external_symlinks,
                overwrite,
                ignore_zeros,
                obj: Mutex::new(obj),
                pos: 0.into(),
            }),
        }
    }
}

impl<R: Read + Unpin> Archive<R> {
    /// Create a new archive with the underlying object as the reader.
    pub fn new(obj: R) -> Archive<R> {
        Archive {
            inner: Arc::new(ArchiveInner {
                unpack_xattrs: false,
                preserve_permissions: false,
                preserve_mtime: true,
                allow_external_symlinks: true,
                overwrite: true,
                ignore_zeros: false,
                obj: Mutex::new(obj),
                pos: 0.into(),
            }),
        }
    }

    /// Unwrap this archive, returning the underlying object.
    pub fn into_inner(self) -> Result<R, Self> {
        let Self { inner } = self;

        match Arc::try_unwrap(inner) {
            Ok(inner) => Ok(inner.obj.into_inner()),
            Err(inner) => Err(Self { inner }),
        }
    }

    /// Construct an stream over the entries in this archive.
    ///
    /// Note that care must be taken to consider each entry within an archive in
    /// sequence. If entries are processed out of sequence (from what the
    /// stream returns), then the contents read for each entry may be
    /// corrupted.
    pub fn entries(&mut self) -> io::Result<Entries<R>> {
        if self.inner.pos.load(Ordering::SeqCst) != 0 {
            return Err(other(
                "cannot call entries unless archive is at \
                 position 0",
            ));
        }

        let limits = Limits::permissive();
        let mut parser = Parser::new(limits);
        parser.set_allow_empty_path(true);
        Ok(Entries {
            archive: self.clone(),
            parser,
            buf: Vec::new(),
            filled: 0,
            next: 0,
            done: false,
        })
    }

    /// Construct an stream over the raw entries in this archive.
    ///
    /// Note that care must be taken to consider each entry within an archive in
    /// sequence. If entries are processed out of sequence (from what the
    /// stream returns), then the contents read for each entry may be
    /// corrupted.
    pub fn entries_raw(&mut self) -> io::Result<RawEntries<R>> {
        if self.inner.pos.load(Ordering::SeqCst) != 0 {
            return Err(other(
                "cannot call entries_raw unless archive is at \
                 position 0",
            ));
        }

        Ok(RawEntries {
            archive: self.clone(),
            current: (0, None, 0),
        })
    }

    /// Unpacks the contents tarball into the specified `dst`.
    ///
    /// This function will iterate over the entire contents of this tarball,
    /// extracting each file in turn to the location specified by the entry's
    /// path name.
    ///
    /// This operation is relatively sensitive in that it will not write files
    /// outside of the path specified by `dst`. Files in the archive which have
    /// a '..' in their path are skipped during the unpacking process.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> { tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// #
    /// use tokio::fs::File;
    /// use tokio_tar::Archive;
    ///
    /// let mut ar = Archive::new(File::open("foo.tar").await?);
    /// ar.unpack("foo").await?;
    /// #
    /// # Ok(()) }) }
    /// ```
    pub async fn unpack<P: AsRef<Path>>(&mut self, dst: P) -> io::Result<()> {
        let mut entries = self.entries()?;
        let mut pinned = Pin::new(&mut entries);
        let dst = dst.as_ref();

        if fs::symlink_metadata(dst).await.is_err() {
            fs::create_dir_all(&dst)
                .await
                .map_err(|e| TarError::new(format!("failed to create `{}`", dst.display()), e))?;
        }

        // Canonicalizing the dst directory will prepend the path with '\\?\'
        // on windows which will allow windows APIs to treat the path as an
        // extended-length path with a 32,767 character limit. Otherwise all
        // unpacked paths over 260 characters will fail on creation with a
        // NotFound exception.
        let dst = fs::canonicalize(dst).await?;

        // Memoize filesystem calls to canonicalize paths.
        let mut targets = FxHashSet::default();

        // Delay any directory entries until the end (they will be created if needed by
        // descendants), to ensure that directory permissions do not interfere with descendant
        // extraction.
        let mut directories = Vec::new();
        while let Some(entry) = pinned.next().await {
            let mut file = entry.map_err(|e| TarError::new("failed to iterate over archive", e))?;
            if file.header().entry_type() == crate::EntryType::Directory {
                directories.push(file);
            } else {
                file.unpack_in_raw(&dst, &mut targets).await?;
            }
        }

        // Apply the directories.
        //
        // Note: the order of application is important to permissions. That is, we must traverse
        // the filesystem graph in topological ordering or else we risk not being able to create
        // child directories within those of more restrictive permissions. See [0] for details.
        //
        // [0]: <https://github.com/alexcrichton/tar-rs/issues/242>
        directories.sort_by(|a, b| b.path_bytes().cmp(&a.path_bytes()));
        for mut dir in directories {
            dir.unpack_in_raw(&dst, &mut targets).await?;
        }

        Ok(())
    }
}

/// Stream of `Entry`s.
pub struct Entries<R: Read + Unpin> {
    archive: Archive<R>,
    parser: Parser,
    buf: Vec<u8>,
    /// Number of bytes in `buf` that contain valid data.
    filled: usize,
    /// Byte offset in the archive where the next header/content starts.
    next: u64,
    done: bool,
}

/// Map tar-core parse errors to io::Error with messages compatible with
/// existing tar-rs error strings.
fn parse_error_to_io(e: ParseError) -> io::Error {
    let msg = match e {
        ParseError::InvalidSize(_) => "size overflow".to_string(),
        other_err => other_err.to_string(),
    };
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Owned entry metadata extracted from a borrowed `ParsedEntry`.
///
/// Consuming the `ParsedEntry` fields into owned data releases the borrow
/// on the parser's input buffer, letting `finish_entry` take `&mut self`.
struct EntryMeta {
    consumed: usize,
    header: Header,
    content_size: u64,
    padded_content_size: u64,
    long_pathname: Option<Vec<u8>>,
    long_linkname: Option<Vec<u8>>,
    pax_extensions: Option<Vec<u8>>,
    sparse: Option<(Vec<CoreSparseEntry>, u64)>,
}

impl EntryMeta {
    fn from_parsed(
        consumed: usize,
        entry: tar_core::parse::ParsedEntry<'_>,
        sparse: Option<(Vec<CoreSparseEntry>, u64)>,
    ) -> Self {
        let mut header = Header::new_old();
        header
            .as_mut_bytes()
            .copy_from_slice(entry.header.as_bytes());
        header.set_uid(entry.uid);
        header.set_gid(entry.gid);

        let content_size = entry.size;
        let padded_content_size = entry.padded_size();

        let long_pathname = if entry.path.as_ref() != entry.header.path_bytes() {
            Some(entry.path.into_owned())
        } else {
            None
        };

        let long_linkname = entry.link_target.and_then(|lt| {
            let header_link = entry.header.link_name_bytes();
            if lt.as_ref() != header_link {
                Some(lt.into_owned())
            } else {
                None
            }
        });

        Self {
            consumed,
            header,
            content_size,
            padded_content_size,
            long_pathname,
            long_linkname,
            pax_extensions: entry.pax,
            sparse,
        }
    }
}

impl<R: Read + Unpin> Entries<R> {
    /// Finish constructing an entry from its owned metadata.
    fn finish_entry(&mut self, meta: EntryMeta) -> io::Result<Entry<Archive<R>>> {
        // `self.next` still points to where the current header chain started
        // (we haven't updated it yet). The archive stream position has
        // advanced past the header bytes we read.
        let header_pos = self.next;
        let file_pos = self.next + meta.consumed as u64;

        // Build the I/O chain.
        let (data, size) = if let Some((sparse_map, real_size)) = meta.sparse {
            let data =
                self.build_sparse_io(&sparse_map, real_size, meta.content_size)?;
            (data, real_size)
        } else {
            let mut data = VecDeque::with_capacity(1);
            data.push_back(EntryIo::Data(self.archive.clone().take(meta.content_size)));
            (data, meta.content_size)
        };

        self.next = file_pos
            .checked_add(meta.padded_content_size)
            .ok_or_else(|| other("size overflow"))?;

        let fields = EntryFields {
            size,
            header_pos,
            file_pos,
            data,
            header: meta.header,
            long_pathname: meta.long_pathname,
            long_linkname: meta.long_linkname,
            pax_extensions: meta.pax_extensions,
            unpack_xattrs: self.archive.inner.unpack_xattrs,
            preserve_permissions: self.archive.inner.preserve_permissions,
            preserve_mtime: self.archive.inner.preserve_mtime,
            overwrite: self.archive.inner.overwrite,
            allow_external_symlinks: self.archive.inner.allow_external_symlinks,
            read_state: None,
        };

        Ok(fields.into_entry())
    }

    /// Build the sparse I/O chain from a tar-core sparse map.
    fn build_sparse_io(
        &self,
        sparse_map: &[CoreSparseEntry],
        real_size: u64,
        on_disk_size: u64,
    ) -> io::Result<VecDeque<EntryIo<Archive<R>>>> {
        let mut data = VecDeque::new();
        let mut cur = 0u64;
        let mut remaining = on_disk_size;

        for block in sparse_map {
            let off = block.offset;
            let len = block.length;

            if len != 0 && (on_disk_size - remaining) % BLOCK_SIZE != 0 {
                return Err(other(
                    "previous block in sparse file was not \
                     aligned to 512-byte boundary",
                ));
            }
            if off < cur {
                return Err(other(
                    "out of order or overlapping sparse \
                     blocks",
                ));
            }
            if cur < off {
                data.push_back(EntryIo::Pad(io::repeat(0).take(off - cur)));
            }
            cur = off
                .checked_add(len)
                .ok_or_else(|| other("more bytes listed in sparse file than u64 can hold"))?;
            remaining = remaining.checked_sub(len).ok_or_else(|| {
                other(
                    "sparse file consumed more data than the header \
                     listed",
                )
            })?;
            data.push_back(EntryIo::Data(self.archive.clone().take(len)));
        }

        if cur != real_size {
            return Err(other(
                "mismatch in sparse file chunks and \
                 size in header",
            ));
        }
        if remaining > 0 {
            return Err(other(
                "mismatch in sparse file chunks and \
                 entry size in header",
            ));
        }

        Ok(data)
    }
}

impl<R: Read + Unpin> Stream for Entries<R> {
    type Item = io::Result<Entry<Archive<R>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        loop {
            // Step 1: Skip past previous entry's content (if any).
            let skip = this.next.saturating_sub(this.archive.inner.pos.load(Ordering::SeqCst));
            if skip > 0 {
                match futures_core::ready!(poll_skip(&mut this.archive, cx, skip)) {
                    Ok(()) => {}
                    Err(e) => return Poll::Ready(Some(Err(e))),
                }
            }

            // Step 2: Parse with current buffer contents.
            // We extract the metadata into an owned struct to release the
            // borrow on `this.buf` before calling `finish_entry`.
            let event = this
                .parser
                .parse(&this.buf[..this.filled])
                .map_err(parse_error_to_io);
            match event {
                Ok(ParseEvent::NeedData { min_bytes }) => {
                    // Ensure buf has capacity for min_bytes.
                    if this.buf.len() < min_bytes {
                        this.buf.resize(min_bytes, 0);
                    }
                    // Fill from this.filled to min_bytes.
                    while this.filled < min_bytes {
                        let mut read_buf =
                            io::ReadBuf::new(&mut this.buf[this.filled..min_bytes]);
                        match futures_core::ready!(
                            Pin::new(&mut this.archive).poll_read(cx, &mut read_buf)
                        ) {
                            Ok(()) if read_buf.filled().is_empty() => {
                                if this.filled == 0
                                    || this.archive.inner.ignore_zeros
                                {
                                    this.done = true;
                                    return Poll::Ready(None);
                                }
                                return Poll::Ready(Some(Err(other(
                                    "unexpected EOF in archive",
                                ))));
                            }
                            Ok(()) => {
                                this.filled += read_buf.filled().len();
                            }
                            Err(e) => return Poll::Ready(Some(Err(e))),
                        }
                    }
                    // Data is ready, loop back to parse again.
                    continue;
                }
                Ok(ParseEvent::Entry { consumed, entry }) => {
                    let meta = EntryMeta::from_parsed(consumed, entry, None);
                    let result = this.finish_entry(meta);
                    this.buf.clear();
                    this.filled = 0;
                    return Poll::Ready(Some(result));
                }
                Ok(ParseEvent::SparseEntry {
                    consumed,
                    entry,
                    sparse_map,
                    real_size,
                }) => {
                    let meta =
                        EntryMeta::from_parsed(consumed, entry, Some((sparse_map, real_size)));
                    let result = this.finish_entry(meta);
                    this.buf.clear();
                    this.filled = 0;
                    return Poll::Ready(Some(result));
                }
                Ok(ParseEvent::GlobalExtensions { consumed, .. }) => {
                    // Global PAX headers set defaults for subsequent entries.
                    // Consume and continue; tokio-tar historically ignores them.
                    this.buf.drain(..consumed);
                    this.filled = this.filled.saturating_sub(consumed);
                    continue;
                }
                Ok(ParseEvent::End { .. }) => {
                    if this.archive.inner.ignore_zeros {
                        // Reset parser for next concatenated archive.
                        this.buf.clear();
                        this.filled = 0;
                        this.next = this.archive.inner.pos.load(Ordering::SeqCst);
                        this.parser = Parser::new(Limits::permissive());
                        this.parser.set_allow_empty_path(true);
                        continue;
                    }
                    this.done = true;
                    return Poll::Ready(None);
                }
                Err(e) => {
                    return Poll::Ready(Some(Err(e)));
                }
            }
        }
    }
}

/// Stream of raw `Entry`s.
pub struct RawEntries<R: Read + Unpin> {
    archive: Archive<R>,
    current: (u64, Option<Header>, usize),
}

impl<R: Read + Unpin> Stream for RawEntries<R> {
    type Item = io::Result<Entry<Archive<R>>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let archive = self.archive.clone();
        let (next, current_header, current_header_pos) = &mut self.current;
        poll_next_raw(archive, next, current_header, current_header_pos, cx, None)
    }
}

fn poll_next_raw<R: Read + Unpin>(
    mut archive: Archive<R>,
    next: &mut u64,
    current_header: &mut Option<Header>,
    current_header_pos: &mut usize,
    cx: &mut Context<'_>,
    pax_extensions_data: Option<&[u8]>,
) -> Poll<Option<io::Result<Entry<Archive<R>>>>> {
    let mut header_pos = *next;

    loop {
        // Seek to the start of the next header in the archive
        if current_header.is_none() {
            let delta = *next - archive.inner.pos.load(Ordering::SeqCst);
            match futures_core::ready!(poll_skip(&mut archive, cx, delta)) {
                Ok(_) => {}
                Err(err) => return Poll::Ready(Some(Err(err))),
            }

            *current_header = Some(Header::new_old());
            *current_header_pos = 0;
        }

        let header = current_header.as_mut().unwrap();

        // EOF is an indicator that we are at the end of the archive.
        match futures_core::ready!(poll_try_read_all(
            &mut archive,
            cx,
            header.as_mut_bytes(),
            current_header_pos,
        )) {
            Ok(true) => {}
            Ok(false) => return Poll::Ready(None),
            Err(err) => return Poll::Ready(Some(Err(err))),
        }

        // If a header is not all zeros, we have another valid header.
        // Otherwise, check if we are ignoring zeros and continue, or break as if this is the
        // end of the archive.
        if !header.as_bytes().iter().all(|i| *i == 0) {
            *next += BLOCK_SIZE;
            break;
        }

        if !archive.inner.ignore_zeros {
            return Poll::Ready(None);
        }

        *next += BLOCK_SIZE;
        header_pos = *next;
    }

    let header = current_header.as_mut().unwrap();

    // Make sure the checksum is ok
    let sum = header.as_bytes()[..148]
        .iter()
        .chain(&header.as_bytes()[156..])
        .fold(0, |a, b| a + (*b as u32))
        + 8 * 32;
    let cksum = header.cksum()?;
    if sum != cksum {
        return Poll::Ready(Some(Err(other("archive header checksum mismatch"))));
    }

    let file_pos = *next;

    let mut header = current_header.take().unwrap();

    // note when pax extensions are available, the size from the header will be ignored
    let mut size = header.entry_size()?;

    // the size above will be overriden by the pax data if it has a size field.
    // same for uid and gid, which will be overridden in the header itself.
    if let Some(pax) = pax_extensions_data.map(PaxExtensions::new) {
        for extension in pax {
            let extension = extension?;

            // ignore keys that aren't parsable as a string at this stage.
            // that isn't relevant to the size/uid/gid processing.
            let Ok(key) = extension.key() else {
                continue;
            };

            match key {
                "size" => {
                    let size_str = extension
                        .value()
                        .map_err(|_e| other("failed to parse pax size as string"))?;
                    size = size_str
                        .parse::<u64>()
                        .map_err(|_e| other("failed to parse pax size"))?;
                }

                "uid" => {
                    let uid_str = extension
                        .value()
                        .map_err(|_e| other("failed to parse pax uid as string"))?;
                    header.set_uid(
                        uid_str
                            .parse::<u64>()
                            .map_err(|_e| other("failed to parse pax uid"))?,
                    );
                }

                "gid" => {
                    let gid_str = extension
                        .value()
                        .map_err(|_e| other("failed to parse pax gid as string"))?;
                    header.set_gid(
                        gid_str
                            .parse::<u64>()
                            .map_err(|_e| other("failed to parse pax gid"))?,
                    );
                }

                _ => {
                    continue;
                }
            }
        }
    }

    let mut data = VecDeque::with_capacity(1);
    data.push_back(EntryIo::Data(archive.clone().take(size)));

    let ret = EntryFields {
        size,
        header_pos,
        file_pos,
        data,
        header,
        long_pathname: None,
        long_linkname: None,
        pax_extensions: None,
        unpack_xattrs: archive.inner.unpack_xattrs,
        preserve_permissions: archive.inner.preserve_permissions,
        preserve_mtime: archive.inner.preserve_mtime,
        overwrite: archive.inner.overwrite,
        allow_external_symlinks: archive.inner.allow_external_symlinks,
        read_state: None,
    };

    // Store where the next entry is, rounding up by 512 bytes (the size of
    // a header);
    let size = size
        .checked_add(BLOCK_SIZE - 1)
        .ok_or_else(|| other("size overflow"))?;
    *next = next
        .checked_add(size & !(BLOCK_SIZE - 1))
        .ok_or_else(|| other("size overflow"))?;

    Poll::Ready(Some(Ok(ret.into_entry())))
}

impl<R: Read + Unpin> Read for Archive<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        into: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut r = if let Ok(v) = self.inner.obj.try_lock() {
            v
        } else {
            return Poll::Pending;
        };

        let res = futures_core::ready!(Pin::new(&mut *r).poll_read(cx, into));
        match res {
            Ok(()) => {
                self.inner
                    .pos
                    .fetch_add(into.filled().len() as u64, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

/// Try to fill the buffer from the reader.
///
/// If the reader reaches its end before filling the buffer at all, returns `false`.
/// Otherwise returns `true`.
fn poll_try_read_all<R: Read + Unpin>(
    mut source: R,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    pos: &mut usize,
) -> Poll<io::Result<bool>> {
    while *pos < buf.len() {
        let mut read_buf = io::ReadBuf::new(&mut buf[*pos..]);
        match futures_core::ready!(Pin::new(&mut source).poll_read(cx, &mut read_buf)) {
            Ok(()) if read_buf.filled().is_empty() => {
                if *pos == 0 {
                    return Poll::Ready(Ok(false));
                }

                return Poll::Ready(Err(other("failed to read entire block")));
            }
            Ok(()) => *pos += read_buf.filled().len(),
            Err(err) => return Poll::Ready(Err(err)),
        }
    }

    *pos = 0;
    Poll::Ready(Ok(true))
}

/// Skip n bytes on the given source.
fn poll_skip<R: Read + Unpin>(
    mut source: R,
    cx: &mut Context<'_>,
    mut amt: u64,
) -> Poll<io::Result<()>> {
    let mut buf = [0u8; 4096 * 8];
    while amt > 0 {
        let n = cmp::min(amt, buf.len() as u64);
        let mut read_buf = io::ReadBuf::new(&mut buf[..n as usize]);
        match futures_core::ready!(Pin::new(&mut source).poll_read(cx, &mut read_buf)) {
            Ok(()) if read_buf.filled().is_empty() => {
                return Poll::Ready(Err(other("unexpected EOF during skip")));
            }
            Ok(()) => {
                amt -= read_buf.filled().len() as u64;
            }
            Err(err) => return Poll::Ready(Err(err)),
        }
    }

    Poll::Ready(Ok(()))
}

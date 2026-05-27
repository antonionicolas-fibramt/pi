import { open } from "node:fs/promises";

const IMAGE_TYPE_SNIFF_BYTES = 4100;
const BINARY_SNIFF_BYTES = 8192;
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const PDF_SIGNATURE = [0x25, 0x50, 0x44, 0x46]; // %PDF
const ZIP_SIGNATURE = [0x50, 0x4b, 0x03, 0x04]; // PK\x03\x04 — ods/xlsx/docx/pptx/jar/apk/epub
const ZIP_EMPTY_SIGNATURE = [0x50, 0x4b, 0x05, 0x06]; // empty archive
const ZIP_SPANNED_SIGNATURE = [0x50, 0x4b, 0x07, 0x08]; // spanned archive
const ELF_SIGNATURE = [0x7f, 0x45, 0x4c, 0x46];
const SQLITE_SIGNATURE = [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00];
const GZIP_SIGNATURE = [0x1f, 0x8b];
const SEVEN_ZIP_SIGNATURE = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const RAR_SIGNATURE = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07];
const MP3_ID3_SIGNATURE = [0x49, 0x44, 0x33]; // ID3
const OGG_SIGNATURE = [0x4f, 0x67, 0x67, 0x53]; // OggS
const FLAC_SIGNATURE = [0x66, 0x4c, 0x61, 0x43]; // fLaC

export function detectSupportedImageMimeType(buffer: Uint8Array): string | null {
	if (startsWith(buffer, [0xff, 0xd8, 0xff])) {
		return buffer[3] === 0xf7 ? null : "image/jpeg";
	}
	if (startsWith(buffer, PNG_SIGNATURE)) {
		return isPng(buffer) && !isAnimatedPng(buffer) ? "image/png" : null;
	}
	if (startsWithAscii(buffer, 0, "GIF")) {
		return "image/gif";
	}
	if (startsWithAscii(buffer, 0, "RIFF") && startsWithAscii(buffer, 8, "WEBP")) {
		return "image/webp";
	}
	return null;
}

export async function detectSupportedImageMimeTypeFromFile(filePath: string): Promise<string | null> {
	const fileHandle = await open(filePath, "r");
	try {
		const buffer = Buffer.alloc(IMAGE_TYPE_SNIFF_BYTES);
		const { bytesRead } = await fileHandle.read(buffer, 0, IMAGE_TYPE_SNIFF_BYTES, 0);
		return detectSupportedImageMimeType(buffer.subarray(0, bytesRead));
	} finally {
		await fileHandle.close();
	}
}

/**
 * Detect non-image binary files by magic bytes plus a NUL-byte heuristic.
 *
 * Returns a short label (e.g. "PDF", "ZIP-based archive (Office, jar, apk, ...)",
 * "binary") when the file looks binary, or null when the content appears to be
 * text. Used by the `read` tool to avoid handing the model a `buffer.toString("utf-8")`
 * of raw binary bytes, which corrupts downstream persistence (NUL bytes in jsonb)
 * and degrades the conversation (the model receives a gibberish blob).
 *
 * The check is conservative: known text-shaped formats (JSON, XML, source code,
 * even with no magic bytes) all return null because they have no NUL bytes in
 * the first 8 KB.
 */
export function detectNonImageBinaryLabel(buffer: Uint8Array): string | null {
	if (startsWith(buffer, PDF_SIGNATURE)) return "PDF";
	if (
		startsWith(buffer, ZIP_SIGNATURE) ||
		startsWith(buffer, ZIP_EMPTY_SIGNATURE) ||
		startsWith(buffer, ZIP_SPANNED_SIGNATURE)
	) {
		return "ZIP-based archive (Office document, jar, apk, epub, ...)";
	}
	if (startsWith(buffer, ELF_SIGNATURE)) return "ELF executable";
	if (startsWith(buffer, SQLITE_SIGNATURE)) return "SQLite database";
	if (startsWith(buffer, GZIP_SIGNATURE)) return "gzip";
	if (startsWith(buffer, SEVEN_ZIP_SIGNATURE)) return "7-Zip archive";
	if (startsWith(buffer, RAR_SIGNATURE)) return "RAR archive";
	if (startsWith(buffer, MP3_ID3_SIGNATURE)) return "MP3 (ID3-tagged)";
	if (startsWith(buffer, OGG_SIGNATURE)) return "Ogg media";
	if (startsWith(buffer, FLAC_SIGNATURE)) return "FLAC audio";
	// MP3 frame sync: 0xFF followed by 0xFB / 0xFA / 0xF3 / 0xF2.
	if (buffer.length >= 2 && buffer[0] === 0xff && [0xfb, 0xfa, 0xf3, 0xf2].includes(buffer[1] ?? -1)) {
		return "MP3 audio";
	}
	// RIFF container — WAV / AVI / WEBP. WEBP is handled by the image sniff above
	// and would never reach this function; flag the rest as binary.
	if (startsWithAscii(buffer, 0, "RIFF") && !startsWithAscii(buffer, 8, "WEBP")) {
		return "RIFF container (WAV/AVI/...)";
	}
	// MP4 / QuickTime: 4 size bytes + "ftyp".
	if (buffer.length >= 12 && startsWithAscii(buffer, 4, "ftyp")) {
		return "MP4/QuickTime media";
	}
	// Final heuristic: NUL bytes in the first 8 KB. Real text files (UTF-8) do
	// not contain NUL. UTF-16/UTF-32 files do, but they are rare and would be
	// mojibake under .toString("utf-8") anyway — flagging them as binary is the
	// safer call.
	const probe = buffer.subarray(0, Math.min(buffer.length, BINARY_SNIFF_BYTES));
	if (probe.indexOf(0) !== -1) return "binary";
	return null;
}

function isPng(buffer: Uint8Array): boolean {
	return (
		buffer.length >= 16 && readUint32BE(buffer, PNG_SIGNATURE.length) === 13 && startsWithAscii(buffer, 12, "IHDR")
	);
}

function isAnimatedPng(buffer: Uint8Array): boolean {
	let offset = PNG_SIGNATURE.length;
	while (offset + 8 <= buffer.length) {
		const chunkLength = readUint32BE(buffer, offset);
		const chunkTypeOffset = offset + 4;
		if (startsWithAscii(buffer, chunkTypeOffset, "acTL")) return true;
		if (startsWithAscii(buffer, chunkTypeOffset, "IDAT")) return false;

		const nextOffset = offset + 8 + chunkLength + 4;
		if (nextOffset <= offset || nextOffset > buffer.length) return false;
		offset = nextOffset;
	}
	return false;
}

function readUint32BE(buffer: Uint8Array, offset: number): number {
	return (
		(buffer[offset] ?? 0) * 0x1000000 +
		((buffer[offset + 1] ?? 0) << 16) +
		((buffer[offset + 2] ?? 0) << 8) +
		(buffer[offset + 3] ?? 0)
	);
}

function startsWith(buffer: Uint8Array, bytes: number[]): boolean {
	if (buffer.length < bytes.length) return false;
	return bytes.every((byte, index) => buffer[index] === byte);
}

function startsWithAscii(buffer: Uint8Array, offset: number, text: string): boolean {
	if (buffer.length < offset + text.length) return false;
	for (let index = 0; index < text.length; index++) {
		if (buffer[offset + index] !== text.charCodeAt(index)) return false;
	}
	return true;
}

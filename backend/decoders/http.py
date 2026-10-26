"""HTTP decoder."""
from .base import BaseDecoder, DecodedLayer


class HTTPDecoder(BaseDecoder):
    """Decode HTTP packets (best-effort)."""

    def supports(self, packet_bytes: bytes) -> bool:
        """HTTP decoder supports packets that look like HTTP request or response."""
        if len(packet_bytes) < 4:
            return False
        # Check for common HTTP methods
        methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']
        for method in methods:
            if packet_bytes.startswith(method):
                return True
        # Check for HTTP response status line
        if packet_bytes.startswith(b'HTTP/'):
            return True
        return False

    def decode(self, packet_bytes: bytes) -> DecodedLayer:
        """Decode HTTP data and return a DecodedLayer."""
        layer = DecodedLayer("HTTP")
        try:
            # Decode bytes to string for parsing, but keep original bytes for raw field
            # We'll use 'utf-8' with errors='replace' to avoid crashes on non-text.
            text = packet_bytes.decode('utf-8', errors='replace')
        except Exception:
            # If we can't decode as text, we still can show raw hex
            layer.add_field("error", "Cannot decode as UTF-8 text")
            layer.add_field("raw_length", len(packet_bytes))
            return layer

        # Look for the end of headers (double CRLF)
        # Note: HTTP uses CRLF as line terminator.
        header_end = text.find('\\r\\n\\r\\n')
        if header_end == -1:
            # Maybe we don't have the full headers yet
            layer.add_field("incomplete", True)
            layer.add_field("raw_preview", text[:200])
            return layer

        headers_part = text[:header_end]
        body = text[header_end+4:]  # skip '\\r\\n\\r\\n'

        # Parse the first line
        lines = headers_part.split('\\r\\n')
        if not lines:
            layer.add_field("error", "No headers found")
            return layer

        first_line = lines[0]
        # Determine if it's a request or response
        if first_line.startswith('HTTP/'):
            # Response
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                version = parts[0]
                status_code = parts[1]
                reason_phrase = parts[2] if len(parts) > 2 else ''
                layer.add_field("message_type", "response")
                layer.add_field("http_version", version)
                layer.add_field("status_code", status_code)
                layer.add_field("reason_phrase", reason_phrase)
            else:
                layer.add_field("error", "Malformed response status line")
                layer.add_field("raw_line", first_line)
        else:
            # Request
            parts = first_line.split(' ', 2)
            if len(parts) >= 3:
                method = parts[0]
                path = parts[1]
                version = parts[2] if len(parts) > 2 else ''
                layer.add_field("message_type", "request")
                layer.add_field("method", method)
                layer.add_field("path", path)
                layer.add_field("http_version", version)
            else:
                layer.add_field("error", "Malformed request line")
                layer.add_field("raw_line", first_line)

        # Parse headers (simplified: just store as raw or parse into dict)
        # We'll store headers as a list of (name, value) tuples
        headers = []
        for line in lines[1:]:
            if line == '':
                continue
            if ': ' in line:
                name, value = line.split(': ', 1)
                headers.append((name.strip(), value.strip()))
            else:
                # Malformed header line
                headers.append((line, ''))
        if headers:
            layer.add_field("headers_count", len(headers))
            # Store first few headers as examples
            for i, (name, value) in enumerate(headers[:5]):
                layer.add_field(f"header_{i}_name", name)
                layer.add_field(f"header_{i}_value", value)
            if len(headers) > 5:
                layer.add_field("headers_truncated", True)
                layer.add_field("headers_total", len(headers))

        layer.add_field("body_length", len(body))
        # Optionally, we could try to decode the body as well, but we'll skip for now.
        layer.add_field("payload_offset", len(packet_bytes))  # consumed all bytes

        return layer
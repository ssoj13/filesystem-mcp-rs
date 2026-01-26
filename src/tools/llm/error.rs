pub fn classify_provider_error(error_msg: &str) -> String {
    let error_lower = error_msg.to_lowercase();

    if error_lower.contains("error parsing chunk") && error_lower.contains("expecting property name") {
        return "Streaming parsing error (malformed JSON chunk). Retry or disable streaming.".to_string();
    }

    if error_lower.contains("function_declarations") && error_lower.contains("format") {
        if error_lower.contains("only 'enum' and 'date-time' are supported") {
            return "Tool schema error: provider supports only 'enum' and 'date-time' string formats.".to_string();
        }
        return "Tool schema validation error. Check tool parameter definitions for unsupported formats.".to_string();
    }

    if error_lower.contains("rate limit") || error_lower.contains("quota") {
        return "Rate limit or quota exceeded. Please wait and retry.".to_string();
    }

    if error_lower.contains("api key")
        || error_lower.contains("authentication")
        || error_lower.contains("unauthorized")
    {
        return "API key error. Check your provider API key and permissions.".to_string();
    }

    if error_lower.contains("parsing") || error_lower.contains("json") || error_lower.contains("malformed") {
        return "Response parsing error. Retry the request.".to_string();
    }

    if error_lower.contains("connection") || error_lower.contains("timeout") {
        return "Connection or timeout error. Check connectivity and retry.".to_string();
    }

    if error_lower.contains("safety") || (error_lower.contains("content") && error_lower.contains("filter")) {
        return "Content filtered by provider safety systems. Modify the request.".to_string();
    }

    if error_lower.contains("token") && (error_lower.contains("limit") || error_lower.contains("exceed")) {
        return "Token limit exceeded. Reduce request size or increase max_tokens.".to_string();
    }

    error_msg.to_string()
}

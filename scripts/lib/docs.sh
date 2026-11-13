#!/usr/bin/env bash
# Documentation functions

# SCRIPT_DIR and ROOT_DIR are inherited from main.sh

function docs_build() {
    info "Building documentation for GitHub Pages"
    local DOCS_ROOT="$ROOT_DIR/docs"
    local DIST_DIR="$DOCS_ROOT/dist"

    info "Cleaning previous build..."
    rm -rf "$DIST_DIR"

    if [ -d "$DOCS_ROOT/books" ]; then
        info "Building mdbook..."
        cd "$DOCS_ROOT/books"
        mdbook build
        cd "$ROOT_DIR"
    fi

    info "Copying architecture diagrams..."
    mkdir -p "$DIST_DIR/architecture"
    if [ -f "$DOCS_ROOT/architecture/high-level-architecture.svg" ]; then
        cp "$DOCS_ROOT/architecture/high-level-architecture.svg" "$DIST_DIR/architecture/"
    fi
    if [ -f "$DOCS_ROOT/architecture/high-level-architecture.mmd" ]; then
        cp "$DOCS_ROOT/architecture/high-level-architecture.mmd" "$DIST_DIR/architecture/"
    fi

    info "Copying Swagger documentation..."
    mkdir -p "$DIST_DIR/swagger"
    if [ -f "$DOCS_ROOT/swagger/swagger.yaml" ]; then
        cp "$DOCS_ROOT/swagger/swagger.yaml" "$DIST_DIR/swagger/"
    fi

    info "Creating Swagger UI page..."
    cat > "$DIST_DIR/swagger/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Gorape API - Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; padding:0; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            window.ui = SwaggerUIBundle({
                url: "./swagger.yaml",
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
EOF

    info "Generating godoc HTML..."
    mkdir -p "$DIST_DIR/godoc"
    cat > "$DIST_DIR/godoc/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gorape - Go Documentation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 { color: #333; }
        .package-list {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .package-list ul {
            list-style: none;
            padding: 0;
        }
        .package-list li {
            margin: 10px 0;
        }
        .package-list a {
            color: #0366d6;
            text-decoration: none;
        }
        .package-list a:hover {
            text-decoration: underline;
        }
        .back-link {
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <h1>Gorape - Go Documentation</h1>
    <p>Go package documentation for Gorape device trust service.</p>
    
    <div class="package-list">
        <h2>Available on pkg.go.dev</h2>
        <ul>
            <li><a href="https://pkg.go.dev/github.com/Gorapeflutter/gorape" target="_blank">github.com/Gorapeflutter/gorape</a> - Main package</li>
            <li><a href="https://pkg.go.dev/github.com/Gorapeflutter/gorape/pkg/server" target="_blank">pkg/server</a> - HTTP server implementation</li>
            <li><a href="https://pkg.go.dev/github.com/Gorapeflutter/gorape/pkg/client" target="_blank">pkg/client</a> - CLI client implementations</li>
            <li><a href="https://pkg.go.dev/github.com/Gorapeflutter/gorape/pkg/config" target="_blank">pkg/config</a> - Configuration management</li>
            <li><a href="https://pkg.go.dev/github.com/Gorapeflutter/gorape/pkg/entity" target="_blank">pkg/entity</a> - Data models and DTOs</li>
        </ul>
    </div>

    <h2>Local Documentation</h2>
    <p>To view documentation locally, run:</p>
    <pre><code>godoc -http=:6060
open http://localhost:6060/pkg/github.com/Gorapeflutter/gorape/</code></pre>

    <div class="back-link">
        <a href="../">← Back to Documentation Home</a>
    </div>
</body>
</html>
EOF

    touch "$DIST_DIR/.nojekyll"
    success "Documentation build complete: $DIST_DIR"
}

function docs_serve() {
    local DOCS_ROOT="$ROOT_DIR/docs"
    local DIST_DIR="$DOCS_ROOT/dist"
    
    if [ ! -d "$DIST_DIR" ]; then
        warn "Dist directory not found, building first..."
        docs_build
    fi

    info "Serving documentation on http://localhost:8000"
    cd "$DIST_DIR"
    python3 -m http.server 8000
}

function docs_architecture() {
    info "Generating architecture SVG from mermaid file"
    local DOCS_DIR="$ROOT_DIR/docs/architecture"
    local MMD_FILE="$DOCS_DIR/high-level-architecture.mmd"
    local SVG_FILE="$DOCS_DIR/high-level-architecture.svg"

    if ! command -v mmdc &> /dev/null; then
        err "mmdc (mermaid-cli) is not installed."
        echo "Please install it with:"
        echo "  npm install -g @mermaid-js/mermaid-cli"
        exit 1
    fi

    info "Generating architecture diagram..."
    mmdc -i "$MMD_FILE" -o "$SVG_FILE" -b transparent
    success "Successfully generated: $SVG_FILE"
}

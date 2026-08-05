#!/bin/bash

# ========================================================================
#  MESSENGER CLI with RSA Encryption
# ========================================================================

API="http://localhost:8080"
KEY_DIR="$HOME/.messenger_keys"
TOKEN_FILE="$HOME/.messenger_token"
PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

mkdir -p "$KEY_DIR"

check_auth() {
    if [ ! -f "$TOKEN_FILE" ]; then
        echo -e "${RED}❌ Not logged in. Run: $0 login <username> <password>${NC}"
        return 1
    fi
    return 0
}

get_token() {
    cat "$TOKEN_FILE" 2>/dev/null
}

api_get() {
    local token=$(get_token)
    curl -s -X GET "$API$1" -H "Authorization: Bearer $token" -H "Content-Type: application/json"
}

api_post() {
    local token=$(get_token)
    curl -s -X POST "$API$1" -H "Authorization: Bearer $token" -H "Content-Type: application/json" -d "$2"
}

# ========================================================================

cmd_gen_keys() {
    echo -e "${BLUE}🔑 Generating RSA keys...${NC}"
    openssl genrsa -out "$PRIVATE_KEY" 2048 2>/dev/null
    openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY" 2>/dev/null
    echo -e "${GREEN}✅ Keys saved to $KEY_DIR${NC}"
}

cmd_register() {
    local username="$1"
    local password="$2"
    
    if [ -z "$username" ] || [ -z "$password" ]; then
        echo -e "${RED}❌ Usage: $0 register <username> <password>${NC}"
        return 1
    fi
    
    if [ ! -f "$PUBLIC_KEY" ]; then
        echo -e "${RED}❌ No public key. Run: $0 gen_keys${NC}"
        return 1
    fi
    
    local pubkey=$(cat "$PUBLIC_KEY" | sed 's/"/\\"/g' | tr -d '\n')
    
    echo -e "${BLUE}📝 Registering $username...${NC}"
    
    local response=$(curl -s -X POST "$API/sign_up" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"$username\",\"password\":\"$password\",\"public_key\":\"$pubkey\"}")
    
    if echo "$response" | grep -q "Success"; then
        echo -e "${GREEN}✅ User $username registered!${NC}"
    else
        echo -e "${RED}❌ Registration failed: $response${NC}"
    fi
}

cmd_login() {
    local username="$1"
    local password="$2"
    
    if [ -z "$username" ] || [ -z "$password" ]; then
        echo -e "${RED}❌ Usage: $0 login <username> <password>${NC}"
        return 1
    fi
    
    echo -e "${BLUE}🔐 Logging in as $username...${NC}"
    
    local response=$(curl -s -X POST "$API/sign_in" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"$username\",\"password\":\"$password\"}")
    
    local token=$(echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$token" ]; then
        echo "$token" > "$TOKEN_FILE"
        echo -e "${GREEN}✅ Login successful!${NC}"
    else
        echo -e "${RED}❌ Login failed${NC}"
        return 1
    fi
}

cmd_logout() {
    rm -f "$TOKEN_FILE"
    echo -e "${GREEN}✅ Logged out${NC}"
}

cmd_users() {
    check_auth || return 1
    echo -e "${BLUE}📋 Users:${NC}"
    api_get "/users" | grep -o '"id":[0-9]*,"name":"[^"]*"' | sed 's/"id"://' | sed 's/,"name":"/ - /' | sed 's/"//g'
}

cmd_send() {
    local to_user="$1"
    local message="$2"
    
    if [ -z "$to_user" ] || [ -z "$message" ]; then
        echo -e "${RED}❌ Usage: $0 send <user> <message>${NC}"
        return 1
    fi
    
    check_auth || return 1
    
    echo -e "${BLUE}🔍 Looking for $to_user...${NC}"
    
    local users=$(api_get "/users")
    local user_id=$(echo "$users" | grep -o "\"id\":[0-9]*,\"name\":\"$to_user\"" | grep -o '[0-9]*' | head -1)
    
    if [ -z "$user_id" ]; then
        echo -e "${RED}❌ User $to_user not found${NC}"
        return 1
    fi
    
    local pubkey_raw=$(echo "$users" | grep -o "\"name\":\"$to_user\",\"public_key\":\"[^\"]*\"" | sed 's/.*"public_key":"//' | sed 's/".*//')
    
    if [ -z "$pubkey_raw" ]; then
        echo -e "${RED}❌ No public key for $to_user${NC}"
        return 1
    fi
    
    local pem_body=$(echo "$pubkey_raw" | sed 's/-----BEGIN PUBLIC KEY-----//' | sed 's/-----END PUBLIC KEY-----//' | tr -d '\n')
    local pem_file="/tmp/recipient_key_$$.pem"
    echo "-----BEGIN PUBLIC KEY-----" > "$pem_file"
    echo "$pem_body" | fold -w 64 >> "$pem_file"
    echo "-----END PUBLIC KEY-----" >> "$pem_file"
    
    echo -e "${BLUE}🔐 Encrypting...${NC}"
    
    local encrypted=$(echo -n "$message" | openssl rsautl -encrypt -pubin -inkey "$pem_file" 2>/dev/null | base64 -w 0)
    rm -f "$pem_file"
    
    if [ -z "$encrypted" ]; then
        echo -e "${RED}❌ Encryption failed${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Encrypted (${#encrypted} chars)${NC}"
    echo -e "${BLUE}📤 Sending to $to_user...${NC}"
    
    local payload=$(printf '{"toUserId":%d,"text":"%s"}' "$user_id" "$encrypted")
    local response=$(api_post "/send_message" "$payload")
    
    if echo "$response" | grep -q "Success"; then
        echo -e "${GREEN}✅ Message sent!${NC}"
    else
        echo -e "${RED}❌ Failed: $response${NC}"
    fi
}

cmd_dialog() {
    local with_user="$1"
    
    if [ -z "$with_user" ]; then
        echo -e "${RED}❌ Usage: $0 dialog <user>${NC}"
        return 1
    fi
    
    check_auth || return 1
    
    if [ ! -f "$PRIVATE_KEY" ]; then
        echo -e "${RED}❌ Private key not found. Run: $0 gen_keys${NC}"
        return 1
    fi
    
    local users=$(api_get "/users")
    local user_id=$(echo "$users" | grep -o "\"id\":[0-9]*,\"name\":\"$with_user\"" | grep -o '[0-9]*' | head -1)
    
    if [ -z "$user_id" ]; then
        echo -e "${RED}❌ User $with_user not found${NC}"
        return 1
    fi
    
    echo -e "${BLUE}📝 Dialog with $with_user:${NC}"
    echo ""
    
    local messages=$(api_get "/messages/$user_id")
    
    if [ -z "$messages" ] || [ "$messages" = "null" ] || [ "$messages" = "[]" ]; then
        echo -e "${YELLOW}No messages${NC}"
        return 0
    fi
    
    # Разбиваем JSON по объектам
    echo "$messages" | sed 's/{"id":/\n{"id":/g' | grep '{"id":' | while read -r entry; do
        local from=$(echo "$entry" | grep -o '"from":"[^"]*"' | head -1 | cut -d'"' -f4)
        local to=$(echo "$entry" | grep -o '"to":"[^"]*"' | head -1 | cut -d'"' -f4)
        local created=$(echo "$entry" | grep -o '"created":"[^"]*"' | head -1 | cut -d'"' -f4)
        local text=$(echo "$entry" | sed 's/.*"text":"//' | sed 's/","created":.*//')
        
        local decrypted=""
        if [[ "$text" =~ ^[A-Za-z0-9+/=]+$ ]]; then
            decrypted=$(echo "$text" | base64 -d 2>/dev/null | openssl rsautl -decrypt -inkey "$PRIVATE_KEY" 2>/dev/null)
        fi
        
        if [ -n "$decrypted" ]; then
            echo -e "${YELLOW}$from${NC} → ${GREEN}$decrypted${NC} (${BLUE}$created${NC}) 🔓"
        else
            echo -e "${YELLOW}$from${NC} → ${RED}[encrypted]${NC} (${BLUE}$created${NC}) 🔒"
        fi
    done
}

cmd_status() {
    echo -e "${BLUE}📊 Status:${NC}"
    [ -f "$TOKEN_FILE" ] && echo -e "  ${GREEN}✅ Logged in${NC}" || echo -e "  ${RED}❌ Not logged in${NC}"
    [ -f "$PUBLIC_KEY" ] && echo -e "  ${GREEN}✅ Public key${NC}" || echo -e "  ${RED}❌ Public key${NC}"
    [ -f "$PRIVATE_KEY" ] && echo -e "  ${GREEN}✅ Private key${NC}" || echo -e "  ${RED}❌ Private key${NC}"
}

cmd_clean() {
    rm -f "$PRIVATE_KEY" "$PUBLIC_KEY" "$TOKEN_FILE"
    echo -e "${GREEN}✅ Cleaned${NC}"
}

cmd_help() {
    cat << EOF
${BLUE}Messenger CLI with RSA Encryption${NC}

Commands:
  gen_keys                     Generate RSA key pair
  register <user> <pass>       Register new user
  login <user> <pass>          Login
  logout                       Logout
  users                        List all users
  send <user> <message>        Send encrypted message
  dialog <user>                Show dialog with decryption
  status                       Show current status
  clean                        Remove all keys and token

Examples:
  $0 gen_keys
  $0 register alice 123456
  $0 login alice 123456
  $0 send bob "Hello, Bob!"
  $0 dialog bob
EOF
}

case "$1" in
    gen_keys)   cmd_gen_keys ;;
    register)   cmd_register "$2" "$3" ;;
    login)      cmd_login "$2" "$3" ;;
    logout)     cmd_logout ;;
    users)      cmd_users ;;
    send)       cmd_send "$2" "$3" ;;
    dialog)     cmd_dialog "$2" ;;
    status)     cmd_status ;;
    clean)      cmd_clean ;;
    help|-h|--help) cmd_help ;;
    *)
        echo -e "${RED}❌ Unknown command: $1${NC}"
        echo ""
        cmd_help
        exit 1
        ;;
esac
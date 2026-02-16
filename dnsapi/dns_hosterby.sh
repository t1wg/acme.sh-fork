#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_hosterby_info='hoster
Site: hoster.by
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_hosterby
Options:
 hosterby_Access_Key Access Key
 hosterby_OrderID Service DNS order ID
 hosterby_Secret_Key Secret Key
 hosterby_User_ID User ID
OptionsAlt:
'

hosterby_Api="https://serviceapi.hoster.by"

dns_hosterby_add(){
  fulldomain=$1
  txtvalue=$2
    
  _debug fulldomain "$fulldomain"
  _debug txtvalue "$txtvalue"

  hosterby_Access_Key="${hosterby_Access_Key:-$(_readaccountconf_mutable hosterby_Access_Key)}"
  hosterby_Secret_Key="${hosterby_Secret_Key:-$(_readaccountconf_mutable hosterby_Secret_Key)}"
  hosterby_Access_Token="$(_readaccountconf_mutable hosterby_Access_Token)"
  hosterby_Refresh_Token="$(_readaccountconf_mutable hosterby_Refresh_Token)"
  hosterby_OrderID="${hosterby_OrderID:-$(_readaccountconf_mutable hosterby_OrderID)}"
  hosterby_User_ID="${hosterby_User_ID:-$(_readaccountconf_mutable hosterby_User_ID)}"
    
  if [ -z "$hosterby_Access_Token" ] || [ -z "$hosterby_Refresh_Token" ]; then
    _err "You do not specify hosterby api access-token and refresh-token."
    return 1
  fi
  if [ -z "$hosterby_OrderID" ]; then
    _err "You do not specify service DNS order ID."
    return 1
  fi
  if [ -z "$hosterby_User_ID" ]; then
    _err "You do not specify user account ID."
    return 1
  fi
  if ! _hosterby_validate_access_token || ! _hosterby_validate_refresh_token; then
    _debug hosterby_OrderID "$hosterby_OrderID"
    _debug hosterby_User_ID "$hosterby_User_ID"
    if _hosterby_create_new_tokens; then
      _saveaccountconf_mutable hosterby_Access_Token "$hosterby_Access_Token"
      _saveaccountconf_mutable hosterby_Refresh_Token "$hosterby_Refresh_Token"
    else
      _err "creating tokens error"
      return 1
    fi
  fi

  _saveaccountconf_mutable hosterby_Access_Key "$hosterby_Access_Key"
  _saveaccountconf_mutable hosterby_Secret_Key "$hosterby_Secret_Key"    
  _saveaccountconf_mutable hosterby_OrderID "$hosterby_OrderID"
  _saveaccountconf_mutable hosterby_User_ID "$hosterby_User_ID"

  _info "Adding record"
  if _hosterby_add_txt_record; then
    return 0
  else
    return 1
  fi
}

dns_hosterby_rm(){
  fulldomain=$1
  txtvalue=$2
  hosterby_Access_Key="${hosterby_Access_Key:-$(_readaccountconf_mutable hosterby_Access_Key)}"
  hosterby_Secret_Key="${hosterby_Secret_Key:-$(_readaccountconf_mutable hosterby_Secret_Key)}"
  hosterby_Access_Token="$(_readaccountconf_mutable hosterby_Access_Token)"
  hosterby_Refresh_Token="$(_readaccountconf_mutable hosterby_Refresh_Token)"
  hosterby_OrderID="${hosterby_OrderID:-$(_readaccountconf_mutable hosterby_OrderID)}"
  hosterby_User_ID="${hosterby_User_ID:-$(_readaccountconf_mutable hosterby_User_ID)}"

  _debug "delete txt records"
  if _hosterby_delete_txt_record;then
    return 0
  else
    return 1
  fi

}


_hosterby_rest(){
  method=$1
  query="$2"
  data="$3"

  _debug query "$query"
  
  if [ "$method" != "GET" ]; then
    _debug data "$data"
    response="$(_post "$data" "$hosterby_Api/$query" "" "$method" "application/json")"
  else
    response="$(_get "$hosterby_Api/$query" "" "10")"
    _debug test
  fi
    _debug2 "$?"
  if ! printf "%s" "$response" | grep '\"httpCode\": 200' >/dev/null; then
    _debug2 response "$response"
    _err error "$query"
    return 1
  fi
  _debug2 response "$response"
  return 0
}


_hosterby_validate_access_token(){
  _H1="X-User-Id: $hosterby_User_ID"
  _H2="Access-Token: $hosterby_Access_Token"
  if _hosterby_rest GET "token/info/access" ; then
    if _contains "$response" "dateExpires";then
      _access_token_expire_date=$(echo "$response" | _egrep_o "\"dateExpires\": *[^,]*" | cut -d : -f 2 | tr -d " ")
      _debug2 _access_token_expire_date "$_access_token_expire_date"
      if [ "$(_time)" -le "$_access_token_expire_date" ];then
        _info "access token not expired"
        return 0
      else
        _err "access token expired"
        return 1
      fi
    fi
  fi
  return 1
}
_hosterby_validate_refresh_token(){
  _H1="X-User-Id: $hosterby_User_ID"
  _H2="Refresh-Token: $hosterby_Refresh_Token"
  if _hosterby_rest GET "token/info/refresh" ; then
    if _contains "$response" "dateExpires";then
      _refresh_token_expire_date=$(echo "$response" | _egrep_o "\"dateExpires\": *[^,]*" | cut -d : -f 2 | tr -d " ")
      _debug2 _refresh_token_expire_date "$_refresh_token_expire_date"
      if [ "$(_time)" -le "$_refresh_token_expire_date" ];then
        _info "refresh token not expired"
        return 0
      else
        _err "refresh token expired"
        return 1
      fi
    fi
  fi
  return 1
}

_hosterby_refresh_access_token(){
  _H1="X-User-Id: $hosterby_User_ID"
  _H2="Refresh-Token: $hosterby_Refresh_Token"
  if _hosterby_rest PATCH "token/refresh" ; then
    return 0
  fi
  return 1
}

_hosterby_create_new_tokens() {

  _H1="Access-Key: $hosterby_Access_Key"
  _H2="Secret-Key: $hosterby_Secret_Key"

  if _hosterby_rest POST "service/account/create/token"; then

    if _contains "$response" "create_token_success"; then

      hosterby_Access_Token="$(printf '%s\n' "$response" | _egrep_o '"accessToken"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)"

      hosterby_Refresh_Token="$(printf '%s\n' "$response" | _egrep_o '"refreshToken"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)"

      if [ -z "$hosterby_Access_Token" ] || [ -z "$hosterby_Refresh_Token" ]; then
        _err "Failed to parse tokens"
        return 1
      fi

      return 0
    fi

    _err "create_token_success not found"
    return 1
  fi

  return 1
}

_hosterby_add_txt_record(){
  last_char=$(printf '%s' "$fulldomain" | tail -c 1)

  if [ "$last_char" != "." ]; then
    fulldomain="${fulldomain}."
  fi
  body=$(printf '{"name":"%s","ttl":3600,"records":[{"content":"\\"%s\\"","disabled":false}]}' \
              "$fulldomain" "$txtvalue")

  _H1="Access-Token: $hosterby_Access_Token"
  if _hosterby_rest POST "dns/orders/$hosterby_OrderID/records/txt" "$body"; then
    return 0
  else 
    if _contains "$response" "dns_record_already_exist"; then
      if _hosterby_delete_txt_record;then
        if _hosterby_add_txt_record;then
          return 0
        fi
      fi
    fi
  fi
  return 1
}

_hosterby_delete_txt_record(){
  last_char=$(printf '%s' "$fulldomain" | tail -c 1)

  if [ "$last_char" != "." ]; then
    fulldomain="${fulldomain}."
  fi
  _H1="Access-Token: $hosterby_Access_Token"
  if _hosterby_rest DELETE "dns/orders/$hosterby_OrderID/records/txt/$fulldomain"; then
    return 0
  fi
  _err "txt record delete error"
  return 1
}

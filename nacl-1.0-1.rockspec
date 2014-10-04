package = "nacl"
version = "1.0-1"

source = {
  url = "..."
}

dependencies = {
  "lua >= 5.2"
}

build = {
  type = "builtin",
  modules = {
    nacl = {
      "src/lua_nacl.c",
      "src/tweetnacl.c",
      "src/devurandom.c"
    }
  }
}

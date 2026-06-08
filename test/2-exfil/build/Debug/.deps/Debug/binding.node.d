cmd_Debug/binding.node := ln -f "Debug/obj.target/binding.node" "Debug/binding.node" 2>/dev/null || (rm -rf "Debug/binding.node" && cp -af "Debug/obj.target/binding.node" "Debug/binding.node")

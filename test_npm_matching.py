# Simulating what a package.json diff looks like in a GitHub patch
patch_example = '''@@ -1,10 +1,10 @@
 {
   "name": "nodejs-app",
   "version": "1.0.0",
   "description": "Sample Node.js application for SBOM scanning",
   "main": "index.js",
   "dependencies": {
     "express": "4.18.2",
     "axios": "1.4.0",
-    "lodash": "4.17.21",
+    "lodash": "4.17.20",
     "chalk": "4.1.2",
     "dotenv": "16.0.3"
   },'''

lines = patch_example.split('\n')
componentName = "lodash"
currentVersion = "4.17.20"

print("Checking line matching logic:\n")
for i, line in enumerate(lines):
    if not line.startswith('@@'):
        # Check if package is found
        packageFound = componentName in line
        # Check if version is found
        versionFound = currentVersion in line
        
        if packageFound or versionFound:
            print(f"Line {i}: {line}")
            print(f"  Package found: {packageFound}")
            print(f"  Version found: {versionFound}")
            print(f"  Both found: {packageFound and versionFound}")
            print()

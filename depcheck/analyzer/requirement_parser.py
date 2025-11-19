class requirementParse:
    
    def parse_file(self, file_path="requirement.txt"):
        declared = {}
        
        try:
            with open(file_path, "r") as file:
                for module in file:
                    module = module.strip()
                    if not module or module.startswith("#"):
                        continue
                    
                    if "==" in module:
                        pkg, version = module.split("==")
                        declared[pkg.lower()] = version
                    else:
                        declared[module.lower()] = None
        
        except FileNotFoundError:
            print("requirements.txt not found")
            return {}
        
        return declared
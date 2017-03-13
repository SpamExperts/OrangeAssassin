import os
import sys
import yaml

RULES_TYPES = {
    "full", "body", "rawbody", "uri", "meta", "header", "mimeheader", "eval"
}

RULES_SETTINGS = {
    "score", "priority", "describe", "lang", "tflags", "uri_detail"
}

def convert(filename):

    base_name, extension = os.path.splitext(filename)

    if extension == ".pre":
        new_filename = base_name + ".yml"
    elif extension == ".cf":
        new_filename = base_name+ ".yaml"

    with open(filename, "r") as old:
        with open(new_filename, "w+") as new:
            for line in old:

                yaml_dict = {}
                line = ' '.join(line.split()).strip()

                if not line or line.startswith("#") or line.startswith("\n"):
                    continue

                if line.startswith("include"):
                    yaml_dict["include"] = line.split()[1].strip()

                elif line.startswith("loadplugin"):
                    yaml_dict["loadplugin"] = line.split(' ', 1)[1].strip()

                else:
                    rtype = line.split()[0]
                    if rtype in RULES_TYPES:
                        rname = line.split()[1]
                        rvalue = line.split(' ', 2)[2]
                        yaml_dict[rname] = dict()
                        yaml_dict[rname]["type"] = rtype
                        yaml_dict[rname]["value"] = rvalue
                    elif rtype in RULES_SETTINGS:
                        rname = line.split(' ')[1]
                        rvalue = line.split(' ', 2)[2]
                        if rtype == "tflags":
                            yaml_dict[rname] = dict()
                            yaml_dict[rname][rtype] = rvalue.split(' ')
                        elif rtype == "lang":
                            locale = rname
                            rname = rvalue.split(' ', 2)[1]
                            if "describe" in rvalue:
                                desc = rvalue.split(' ', 2)[2]
                                yaml_dict[rname] = dict()
                                yaml_dict[rname][rtype] = dict()
                                yaml_dict[rname][rtype][locale] = desc
                            elif "report" in rvalue:
                                desc = rvalue.split(' ', 1)[1]
                                yaml_dict[rtype] = dict()
                                yaml_dict[rtype][locale] = desc

                        else:
                            yaml_dict[rname] = dict()
                            yaml_dict[rname][rtype] = rvalue
                    else:
                        try:
                            rvalue = line.split(' ', 1)[1]
                            yaml_dict[rtype] = rvalue
                        except IndexError:
                            pass

                yaml.dump(yaml_dict, new, default_flow_style=False)


def main():
    if len(sys.argv) != 2:
        print("Usage: python %s <filename>" % sys.argv[0])
        return

    convert(sys.argv[1])


if __name__ == "__main__":
    main()


import sys, os 
import json


auditfile = "./audit.json"

def main(args):

    #Todo: support file as argument instead if coded
    if os.path.isfile(auditfile) == False:
        print("file not found: ", auditfile)

    #print("using file ", auditfile)
    with open(auditfile) as afile:
        audit = json.load(afile)

    #print("file loaded")

    print("Sumup ")
    for advisory in audit["advisories"].values(): 
        sumup = advisory["module_name"]
        sumup += ", " + advisory["title"]
        for v in advisory["findings"]:
            sumup += "," + v["version"]

        print(sumup)
        

    print("########### \n\n ")

    for advisory in audit["advisories"].values(): 
        print("ID: ", advisory["id"])
        print("Title:", advisory["title"])
        print("Module: ", advisory["module_name"])

        for v in advisory["findings"]:
            print("Version: ", v["version"])
            #for path in v["paths"]:
            #    print("Path: ", path)
        

        print("Vulnerable versions: ", advisory["vulnerable_versions"])
        print("Pathed version: ", advisory["patched_versions"])
        print("Overview: ", advisory["overview"])
        print("Recommencation: ", advisory["recommendation"])      
        print("Access: ", advisory["access"])
        print("Severity: ", advisory["severity"])
        print("CWE: ", advisory["cwe"])
        print("Url: ", advisory["url"])


        print("\n")



#start
if __name__ == '__main__':
    main(sys.argv[1:])
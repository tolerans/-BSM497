import argparse
import os
import mmh3
import sys
import shelve
from similarity_modules import PersistStorage

def main():

    similarity_comp = PersistStorage()

    parser = argparse.ArgumentParser(
        description="""
    Simple code-sharing search system which allows you to build up a database of malware samples (indexed by file paths) and
    then search for similar samples given some new sample
    """
    )

    parser.add_argument(
        "-l","--load",dest="load",default=None,
        help="Path to directory containing malware, or individual malware file, to store in database"
    )

    parser.add_argument(
        "-s","--search",dest="search",default=None,
        help="Individual malware file to perform similarity search on"
    )

    parser.add_argument(
        "-c","--comment",dest="comment",default=None,
        help="Comment on a malware sample path"
    )

    parser.add_argument(
        "-w","--wipe",action="store_true",default=False,
        help="Wipe sample database"
    )

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
    if args.load:
        malware_paths = [] # where we'll store the malware file paths
        malware_attributes = dict() # where we'll store the malware strings
        for root, dirs, paths in os.walk(args.load):
            for path in paths:
                full_path = os.path.join(root,path)
                malware_paths.append(full_path)
                if similarity_comp.pechecker(full_path):
                    similarity_comp.malware_paths.append(full_path)

        # get and store the strings for all of the malware PE files
        for path in malware_paths:
            similarity_comp.store_sample(path)

    if args.search:
        similarity_comp.search_sample(args.search)
    if args.comment:
        similarity_comp.comment_sample(args.comment)
    if args.wipe:
        similarity_comp.wipe_database()



if __name__ == "__main__":
    main()

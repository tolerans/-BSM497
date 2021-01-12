import shelve
import mmh3
import os
import sys
import json
import numpy as np
from colorama import Fore, Style
from modules import StringBasedSimilarity

with open("config.json", "r") as _file:
    config = json.load(_file)

NUM_MINHASHES = config['NUM_MINHASHES']
SKETCH_RATIO = config['SKETCH_RATIO']
DB_NAME = config['DB_NAME']


class PersistStorage(StringBasedSimilarity):

    def __init__(self):
        StringBasedSimilarity.__init__(self,)
        

    def wipe_database(self,):
       
        dbpath = "/".join(__file__.split('/')[:-1] + [DB_NAME])
        os.system("rm -f {0}".format(dbpath))

    def get_database(self,):
        
        dbpath = "/".join(__file__.split('/')[:-1] + [DB_NAME])
        return shelve.open(dbpath,protocol=2,writeback=True)

    def store_sample(self, path):
        
        db = self.get_database()
        attributes = self.getstrings(path)
        minhashes,sketches = self.minhash(attributes)

        for sketch in sketches:
            sketch = str(sketch)
            if not sketch in db:
                db[sketch] = set([path])
            else:
                obj = db[sketch]
                obj.add(path)
                db[sketch] = obj
            db[path] = {'minhashes':minhashes,'comments':[]}
            db.sync()

        print (f"{Fore.YELLOW}Extracted {len(attributes)} attributes from {path} ...{Style.RESET_ALL}")

    def search_sample(self, path):
       
        db = self.get_database()
        attributes = self.getstrings(path)
        minhashes,sketches = self.minhash(attributes)
        neighbors = []

        for sketch in sketches:
            sketch = str(sketch)

            if not sketch in db:
                continue

            for neighbor_path in db[sketch]:
                neighbor_minhashes = db[neighbor_path]['minhashes']
                similarity = (neighbor_minhashes == minhashes).sum() / float(NUM_MINHASHES)
                neighbors.append((neighbor_path,similarity))

        neighbors = list(set(neighbors))
        neighbors.sort(key=lambda entry:entry[1],reverse=True)
        print ("")
        print ("Sample name".ljust(64),"Shared code estimate")
        for neighbor, similarity in neighbors:
            short_neighbor = neighbor.split("/")[-1]
            comments = db[neighbor]['comments']
            print (str("[*] "+short_neighbor).ljust(64),similarity)
            for comment in comments:
                print ("\t[comment]",comment)   

    def minhash(self, attributes):
    
        minhashes: list = []
        sketches: list= []
        for i in range(NUM_MINHASHES):
            minhashes.append(
                min([mmh3.hash_bytes(attribute,i) for attribute in attributes])
            )
        for i in range(0,NUM_MINHASHES, SKETCH_RATIO):
            byte_string = minhashes[i:i+SKETCH_RATIO]
            #sketch = mmh3.hash_bytes(b"".join(byte_string))
            sketch = mmh3.hash_bytes(b"byte_string")
            sketches.append(sketch)
        return np.array(minhashes), sketches
import pefile
import sys
import argparse
import os
import pprint
import logging
import networkx
import collections
import tempfile

from networkx.drawing.nx_agraph import write_dot
from networkx.algorithms import bipartite
from typing import List,Dict

def parsing_command_line():

    args = argparse.ArgumentParser("Visual DLL import Relationships between a directory of malware samples")
    args.add_argument("--target-path", help = "Directory with malware samples")
    args.add_argument("--output-file", help = "File to write dot file too")
    args.add_argument("--malware-projection", help = "File to write dot file too")
    args.add_argument("--resource-projection", help = "File to write dot file too")
    args = args.parse_args()
    return args




class ExtractImages():

    def __init__(self, target_binary):
        self.target_binary = target_binary
        self.image_basedir = None
        self.images = []
        self.args = parsing_command_line()

    def work(self):
        self.image_basedir = tempfile.mkdtemp()
        icondir = os.path.join(self.image_basedir, "icons")
        bitmapdir = os.path.join(self.image_basedir, "bitmaps")
        raw_resources = os.path.join(self.image_basedir, "raw")

        for directory in [icondir, bitmapdir,raw_resources]:
            os.mkdir(directory)

        rawcmd = f"wrestool -x {self.target_binary} -o {raw_resources} 2> \
                  /dev/null"

        bmpcmd = f"mv {raw_resources}/*.bmp {bitmapdir} 2> /dev/null"

        icocmd = f"icotool -x {raw_resources}/*.ico -o {icondir} \
                   2> /dev/null"

        for cmd in [rawcmd, bmpcmd, icocmd]:
            try:
                os.system(cmd)
            except Exception as e:
                pass
        for dirname in [icondir, bitmapdir]:
            for path in os.listdir(dirname):
                logging.info(path)
                path = os.path.join(dirname, path)
                imagehash = hash(open(path).read())
                if path.endswith(".png"):
                    self.images.append((path, imagehash))
                if path.endswith(".bmp"):
                    self.images.append((path, imagehash))

        def clean_up(self):
            os.system("rm -rf {self.image_basedir}")


def main():

    args = parsing_command_line()
    network = networkx.Graph()

    image_objects = []
    for root, dirs, files in os.walk(args.target_path):
        for path in files:
            try:
                pe = pefile.PE(os.path.join(root, path))
            except pefile.PEFormatError:
                continue
            fullpath = os.path.join(root, path)
            images = ExtractImages(fullpath)
            images.work()
            image_objects.append(images)
            for path, image_hash in images.images:
             # set the image attribute on the image nodes to tell GraphViz to
             # render images within these nodes
                if not image_hash in network:
                    network.add_node(image_hash,image=path,label='',type='image')
                node_name = path.split("/")[-1]
                network.add_node(node_name,type="malware")
                network.add_edge(node_name,image_hash)

    write_dot(network, args.output_file)
    malware = set(n for n,d in network.nodes(data=True) if d['type']=='malware')
    resource = set(network) - malware
    malware_network = bipartite.projected_graph(network, malware)
    resource_network = bipartite.projected_graph(network, resource)
    write_dot(malware_network,args.malware_projection)
    write_dot(resource_network,args.resource_projection)





if __name__ == "__main__":
    main()

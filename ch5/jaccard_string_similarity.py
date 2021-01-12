import argparse
import os
from posix import ST_RDONLY
import networkx
from networkx.drawing.nx_pydot import write_dot
import itertools

class StringBasedSimilarity():

    def __init__(self):

        self.malware_paths = [] 
        self.malware_features = dict() 
        

    def jaccard(self, set1, set2):

        intersection = set1.intersection(set2)
        intersection_len = float(len(intersection))
        union = set1.union(set2)
        union_len = float(len(union))
        return intersection_len / union_len

    def getstrings(self, fullpath):

        strings = os.popen("strings '{0}'".format(fullpath)).read()
        strings = set(strings.split("\n"))
        return strings

    def pechecker(self, full_path):
        
        path = open(full_path, "rb").read(2) 
        return path == b"MZ"

def getparser():

    parser = argparse.ArgumentParser(
        description="Identify similarities between malware samples and build similarity graph"
    )
    parser.add_argument(
        "target_directory",
        help="Directory containing malware"
    )
    parser.add_argument(
        "output_dot_file",
        help="Where to save the output graph DOT file"
    )
    parser.add_argument(
        "--jaccard_index_threshold", "-j", dest="threshold", type=float,
        default=0.8, help="Threshold above which to create an 'edge' between samples"
    )

    args = parser.parse_args()

    return args

def main():

    args = getparser()
    similarity_check = StringBasedSimilarity()
    malware_path = []
    
    graph = networkx.Graph() # the similarity graph

    for root, dirs, paths in os.walk(args.target_directory):
        # walk the target directory tree and store all of the file paths
        for path in paths:
            full_path = os.path.join(root, path)
            if similarity_check.pechecker(full_path):
                similarity_check.malware_paths.append(full_path)

    for path in similarity_check.malware_paths:
        features = similarity_check.getstrings(path)
        print ("Extracted {0} features from {1} ...".format(len(features), path))
        similarity_check.malware_features[path] = features
file:///home/aleyhdar/Pictures/Screenshot_20201209_005109.png
        # add each malware file to the graph
        graph.add_node(path, label=os.path.split(path)[-1][:10])

    # iterate through all pairs of malware
    for malware1, malware2 in itertools.combinations(similarity_check.malware_paths, 2):
        
        # compute the jaccard distance for the current pair
        jaccard_index = similarity_check.jaccard(similarity_check.malware_features[malware1], similarity_check.malware_features[malware2])
       
        # if the jaccard distance is above the threshold, add an edge
        if jaccard_index > args.threshold:
            print (malware1, malware2, jaccard_index) 
            graph.add_edge(malware1, malware2, penwidth=1+(jaccard_index-args.threshold)*10)

    # write the graph to disk so we can visualize it
    write_dot(graph, args.output_dot_file)



if __name__ == "__main__":
    main()

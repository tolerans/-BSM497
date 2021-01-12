import argparse
from machine_learning_detection import *

## python3 main.py --malware_paths ../data/malware/ --benignware_paths ../data/benignware/ --evaluate


def getparser(): 
    
    parser = argparse.ArgumentParser("get windows object vectors for files")
    parser.add_argument("--malware_paths",default=None,help="Path to malware training files")
    parser.add_argument("--benignware_paths",default=None,help="Path to benignware training files")
    parser.add_argument("--scan_file_path",default=None,help="File to scan")
    parser.add_argument("--evaluate",default=False,action="store_true",help="Perform cross-validation")

    args = parser.parse_args()
    return args

def main():

    md = MachineLearningDetection()
    hasher = FeatureHasher(20000)
    args = getparser()

    if args.malware_paths and args.benignware_paths and not args.evaluate:
        md.train_detector(args.benignware_paths,args.malware_paths,hasher)
    elif args.scan_file_path:
        md.scan_file(args.scan_file_path)
    elif args.malware_paths and args.benignware_paths and args.evaluate:
        X, y = md.get_training_data(args.benignware_paths,args.malware_paths,hasher)
        md.cv_evaluate(X,y,hasher)
    else:
        print ("[*] You did not specify a path to scan," \
            " nor did you specify paths to malicious and benign training files" \
            " please specify one of these to use the detector.\n")
        args.print_help()


if __name__ == "__main__":
    main()

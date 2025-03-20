#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dataset Downloader Module
This module helps to download common IDS datasets.
"""

import os
import sys
import logging
import argparse
import requests
from tqdm import tqdm
import zipfile
import tarfile

# Add src directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Setup logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ids.download_datasets')

# Dataset definitions
DATASETS = {
    'cicids2017': {
        'name': 'CICIDS2017 Sample',
        'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
        'files': [
            {
                'name': 'Monday-WorkingHours.pcap_ISCX.csv',
                'url': 'http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CSVs/Monday-WorkingHours.pcap_ISCX.csv',
                'size': 120000000  # approximate size in bytes
            }
        ],
        'description': 'CICIDS2017 contains benign and the most up-to-date common attacks traffic data.'
    },
    'nsl-kdd': {
        'name': 'NSL-KDD',
        'url': 'https://www.unb.ca/cic/datasets/nsl.html',
        'files': [
            {
                'name': 'KDDTrain+.txt',
                'url': 'https://www.unb.ca/cic/datasets/nsl-kdd.html',
                'size': 20000000  # approximate size in bytes
            },
            {
                'name': 'KDDTest+.txt',
                'url': 'https://www.unb.ca/cic/datasets/nsl-kdd.html',
                'size': 10000000  # approximate size in bytes
            }
        ],
        'description': 'NSL-KDD is a modified version of the original KDD Cup 1999 dataset.'
    },
    'unsw-nb15': {
        'name': 'UNSW-NB15',
        'url': 'https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/',
        'files': [
            {
                'name': 'UNSW-NB15_1.csv',
                'url': 'https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/a-pcaps.zip',
                'size': 50000000  # approximate size in bytes
            }
        ],
        'description': 'UNSW-NB15 is a dataset that contains a hybrid of real modern normal and synthetic attack activities.'
    }
}

def download_file(url, destination, file_name=None):
    """
    Download a file from the given URL to the destination with progress bar.
    
    Args:
        url (str): URL to download from
        destination (str): Destination directory
        file_name (str, optional): Name to save the file as
    
    Returns:
        str: Path to the downloaded file
    """
    try:
        if file_name is None:
            file_name = url.split('/')[-1]
            
        file_path = os.path.join(destination, file_name)
        
        # Check if file already exists
        if os.path.exists(file_path):
            logger.info(f"File already exists: {file_path}")
            return file_path
        
        logger.info(f"Downloading {url} to {file_path}")
        
        # Make a streaming request
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Get total file size if available
        total_size = int(response.headers.get('content-length', 0))
        
        # Show a progress bar during download
        with open(file_path, 'wb') as f, tqdm(
            desc=file_name,
            total=total_size,
            unit='B',
            unit_scale=True,
            unit_divisor=1024,
        ) as pbar:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    pbar.update(len(chunk))
        
        logger.info(f"Downloaded {file_path}")
        return file_path
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading file: {e}")
        return None

def extract_archive(file_path, destination):
    """
    Extract an archive (zip, tar, tar.gz) to the destination.
    
    Args:
        file_path (str): Path to the archive file
        destination (str): Destination directory
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"Extracting {file_path} to {destination}")
        
        if file_path.endswith('.zip'):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(destination)
        elif file_path.endswith(('.tar', '.tar.gz', '.tgz')):
            with tarfile.open(file_path, 'r:*') as tar_ref:
                tar_ref.extractall(destination)
        else:
            logger.warning(f"Unsupported archive format: {file_path}")
            return False
        
        logger.info(f"Extracted {file_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error extracting archive: {e}")
        return False

def download_dataset(dataset_key, data_dir):
    """
    Download a specific dataset.
    
    Args:
        dataset_key (str): Key of the dataset to download (from DATASETS)
        data_dir (str): Directory to save the dataset to
    
    Returns:
        bool: True if successful, False otherwise
    """
    if dataset_key not in DATASETS:
        logger.error(f"Unknown dataset: {dataset_key}")
        return False
    
    dataset = DATASETS[dataset_key]
    logger.info(f"Downloading dataset: {dataset['name']}")
    logger.info(f"Description: {dataset['description']}")
    
    # Create dataset directory
    dataset_dir = os.path.join(data_dir, dataset_key)
    os.makedirs(dataset_dir, exist_ok=True)
    
    # Download all files for the dataset
    success = True
    for file_info in dataset['files']:
        file_path = download_file(file_info['url'], dataset_dir, file_info['name'])
        if file_path is None:
            success = False
            continue
        
        # Extract if it's an archive
        if file_path.endswith(('.zip', '.tar', '.tar.gz', '.tgz')):
            extract_success = extract_archive(file_path, dataset_dir)
            if not extract_success:
                success = False
    
    return success

def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Download IDS datasets')
    parser.add_argument('--dataset', type=str, choices=DATASETS.keys(), 
                        help='Specific dataset to download')
    parser.add_argument('--list', action='store_true', 
                        help='List available datasets')
    parser.add_argument('--data-dir', type=str, default=None,
                        help='Directory to save datasets to (default: project/data)')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Determine data directory
    if args.data_dir is None:
        # Use project's data directory
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data')
    else:
        data_dir = args.data_dir
    
    os.makedirs(data_dir, exist_ok=True)
    
    # List available datasets if requested
    if args.list:
        logger.info("Available datasets:")
        for key, dataset in DATASETS.items():
            logger.info(f"- {key}: {dataset['name']}")
            logger.info(f"  Description: {dataset['description']}")
            logger.info(f"  URL: {dataset['url']}")
            logger.info(f"  Files: {len(dataset['files'])}")
        return
    
    # Download specific dataset if requested
    if args.dataset:
        success = download_dataset(args.dataset, data_dir)
        if success:
            logger.info(f"Successfully downloaded dataset: {args.dataset}")
        else:
            logger.error(f"Failed to download dataset: {args.dataset}")
        return
    
    # If no specific dataset is requested, download all
    logger.info("Downloading all available datasets:")
    all_success = True
    for key in DATASETS.keys():
        success = download_dataset(key, data_dir)
        if not success:
            all_success = False
    
    if all_success:
        logger.info("Successfully downloaded all datasets")
    else:
        logger.warning("Some datasets failed to download")

if __name__ == "__main__":
    main() 
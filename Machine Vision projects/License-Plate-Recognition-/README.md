# License Plate Recognition System

A computer vision system for detecting and recognizing license plates from images and video streams.

## Features

- License plate detection using edge detection and contour analysis
- Alternative detection method for challenging scenarios
- OCR-based text recognition of license plates
- Real-time processing with camera feed
- Video file processing with output saving
- Interactive camera controls for performance optimization

## Requirements

- Python 3.6+
- OpenCV
- Tesseract OCR
- NumPy
- Other dependencies listed in requirements.txt

## Installation

1. Clone this repository:
```bash
git clone https://github.com/chandranayak89/License-Plate-Recognition-.git
cd License-Plate-Recognition-
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Install Tesseract OCR:
   - Windows: Download and install from [https://github.com/UB-Mannheim/tesseract/wiki](https://github.com/UB-Mannheim/tesseract/wiki)
   - Linux: `sudo apt install tesseract-ocr`
   - Mac: `brew install tesseract`

## Usage

### Demo Application

Run the demo application to test the system with sample images, video files, or camera feed:

```bash
python demo.py
```

The demo provides an interactive menu with options to:
1. Process a sample image
2. Process a video file
3. Process camera feed
4. Exit

### Camera Mode Controls

When using the camera mode:
- Press 'p' to toggle between preview mode and processing mode
- Press '+' to increase frame skipping (faster but less accurate)
- Press '-' to decrease frame skipping (more accurate but slower)
- Press 'q' to quit

### Programming Interface

You can also use the system programmatically:

```python
from preprocessing import load_image, preprocess_image
from plate_detection import detect_plate
from ocr import enhance_and_recognize

# Load and process an image
img = load_image('path/to/image.jpg')
original, edges = preprocess_image(img)

# Detect license plate
result_img, plate_img = detect_plate(original, edges)

# Recognize text
if plate_img is not None:
    plate_text = enhance_and_recognize(plate_img)
    print(f"Detected license plate: {plate_text}")
```

## Project Structure

- `preprocessing.py`: Image preprocessing functions
- `plate_detection.py`: License plate detection algorithms
- `ocr.py`: Text recognition functions
- `video_processing.py`: Video and camera processing
- `deep_learning_detector.py`: Neural network-based detector
- `main.py`: Main application entry point
- `demo.py`: Interactive demo application

## Performance Optimization

The system includes several performance optimization options:
- Frame skipping: Process only every Nth frame
- Resolution scaling: Reduce resolution for faster processing
- Preview mode: Display camera feed without processing

## License

[MIT License](LICENSE) 
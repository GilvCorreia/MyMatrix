# MyMatrix
After my first application (MyCipher) I realized that i needed also to save my bank matrix on the computer safely, so I reused some of the functions and methods
from MyCipher and created MyMatrix.
This application uses AES-256 and SHA-1 to provide confidentiality and integrity to the matrix.
To run this application is pretty easy, if it's the first time, you'll need to create a password and confirm it, then give two
salt numbers (no need to mesmerize them) and then it's asked the size of the matrix and it's contents. After these steps the 
application is installed and ready to use.
There's also the possibility to update one position of the matrix or the whole matrix (-u), also to confirm the integrity of 
the matrix (-c), to view three positions of the matrix (-v), to quit the application (-q) and to remove all files and directories
created on the instalation process rerturning the application to the initial state.

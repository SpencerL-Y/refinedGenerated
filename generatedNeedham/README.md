## refinedGenerated

### Introduction 

This project is the refined version of the prototype tool used for  automatic generation of designs. The code are refined by hand and is able to provide information on how to modify the 


### Installation and Execution

To run the program several libs are required.

#### Requirements
The code is currently compatible with the linux platform.

- python3

```sudo apt-get install python3.7```

- libpcap-dev

```sudo apt-get install libpcap-dev```

- boost

```sudo apt-get install libboost-dev```

- openssl

```sudo apt-get install openssl libssl-dev```

#### Running

After installing the package, go into folder ```/generated``` and run

```python3 compile.py```

This will result in two binaries $\texttt{./Alice}$ and $\texttt{./Bob}$ in the folder. Then make sure that your net adaptor is open and run the bob first and alice later. These two procedures will try to communicate.

```sudo ./Bob```

```sudo ./Alice```
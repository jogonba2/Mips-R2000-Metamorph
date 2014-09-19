/*
 * Copyright 2014 Overxfl0w13
 * Compile: POC MIPS32 Metamorph >gcc -std=c99 mutation_motor.c -o mutation_motor
*/

/** INCLUDES **/
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
/** END OF INCLUDES **/

/** CONSTANTS **/
#define MULTIPLY_FACTOR 3
#define FUNCTIONS_R_SUPPORTED 13
/** END OF CONSTANTS **/

/** PROTOTYPES **/

// Auxiliar functions //
void read_instructions(int*,FILE*,int);
char is_conmutative(char);
void show_shellcode(int*,int);

// Stage of process //
void analyze_code(int*,int*,int);
void code_transformer(int*,int*,int);

// Stages of code transformation //
int replace_instruction(int,int);
int replace_reg_instruction(int,int,int,int);
int fill_with_chunk(int*,int*,int); 
int change_order_instructions(int*,int*,int);

// Checkers //
char is_type_r(int);
char is_type_i(int);
char is_type_j(int);

// Type R Functions //
char get_r_rs(int);
char get_r_rd(int);
char get_r_rt(int);
char get_r_func(int);
int  set_r_rs(int,char);
int  set_r_rt(int,char);
int  set_r_func(int,char);
char is_r_supported(int);
	
/** END OF PROTOTYPES **/

/** DEFINITIONS **/

// Auxiliar Functions //
char is_conmutative(char fcode){ if(fcode==0x20 || fcode==0x18 || fcode==0x25 || fcode==0x26 || fcode==0x24){ return 1; } return 0; }
void read_instructions(int* instructions,FILE* fd,int num_inst){ for(volatile unsigned int i=0x00;i<num_inst;fscanf(fd,"%i",instructions+(i++))); }
void show_shellcode(int* inst,int length){ printf("\t\t\t\t[----Shellcode----]\n\n");for(unsigned volatile int i=0;i<length;printf("0x%08x\n",inst[i++])); }
// End of auxiliar functions //

// Checkers //
char is_type_r(int inst){ return !(inst&0xFC000000!=0); }
char is_type_j(int inst){ return ((inst&0xFC000000)>>25)==1;} 
char is_type_i(int inst){ return !is_type_r(inst) && !is_type_r(inst); }
// End of Chckers //


// Type R Functions //
                                         // Property: signed -> (-1) unsigned, signed always are even and unsigned always are odd
char functions_r_supported[13] = {0x20,0x21,0x24,0x25,0x1A,0x1B,0x18,0x19,0x2A,0x2B,0x22,0x23}; 
char get_r_rs(int inst)      { return ((inst & 0x03E00000)>>21); }
char get_r_rt(int inst)      { return ((inst & 0x001F0000)>>16); }
char get_r_rd(int inst)      { return ((inst & 0x0000F800)>>11); }
char get_r_func(int inst)    { return ((inst & 0x0000003F));     }
char is_r_supported(int fcode){for(volatile unsigned int i=0;i<FUNCTIONS_R_SUPPORTED;i++){if(functions_r_supported[i]==fcode) return 1;} return 0;}
// (->) Refactor the setters 
int  set_r_rs(int inst,char rs){
	int aux = 0x00000000;
	aux |= rs; aux <<= 5;
	aux |= get_r_rt(inst); aux <<= 5;
	aux |= get_r_rd(inst); aux <<= 5;
	aux <<= 6;aux |= get_r_func(inst);
	return aux;
}
int set_r_rt(int inst,char rt){
	int aux = 0x00000000;
	aux |= get_r_rs(inst); aux <<= 5;
	aux |= rt; aux <<= 5;
	aux |= get_r_rd(inst); aux <<= 5;
	aux <<= 6;aux |= get_r_func(inst);
	return aux;
}
int set_r_func(int inst,char func){
	int aux = 0x00000000;
	aux |= get_r_rs(inst); aux <<= 5;
	aux |= get_r_rt(inst); aux <<= 5;
	aux |= get_r_rd(inst); aux <<= 5;
	aux <<= 6;aux |= func;
	return aux;
}
// End of type R functions //

// Type I Functions [Add support] // 
// Type J Functions [Add support] //


// Stages of code transformation //

int replace_instruction(int act_inst,int fcode){ return set_r_func(act_inst,fcode); }
// Change in act_inst the registers to be replaced, if is not 0 replacement is done //
int replace_reg_instruction(int act_inst,int rs,int rd,int rt){}
// The total num of instructions is T = (num_inst * MULTIPLY_FACTOR), calculate num of instructions to add (T-num_inst), aleatorize position(
// this position is irrelevant if code is filled with chunks such as push,pop,(add,sub),(xor,xor),...)
int fill_with_chunk(int* instructions,int* new_shellcode,int num_inst){}
// Initialise a window W with the number of instructions to check in a single iteration, and see if there are conflicts among instructions in a range |W| 
// The index must have been incremented by |W| each iteration
int change_order_instructions(int *instructions,int* new_shellcode,int num_inst){}

// End of Stages of code transformation //


// Stages of process //
void analyze_code(int* instructions,int* new_shellcode,int num_inst){
	int act_inst = 0x00000000;
	for(unsigned volatile int i=0x00;i<num_inst;i++){
		// Here it's possible to add other transformations (move $t1,$t3 = (xor $t1,$t1,$t1;add $t1,$t1,$t3) = (sub $t1,$t1,$t1;or $t1,$t1,$t3) ...)
		printf("Instruction: 0x%08x\n\n",instructions[i]);
		act_inst = instructions[i];
		if(is_type_r(act_inst)){ // Only implemented type R in this POC
			char change_order_regs = rand() % (2);     // Random [0,1] / if 1 -> change order of regs if not changes the logic of instruction.
			char change_instruct   = rand() % (2);     // Random [0,1] / if 1 -> change instruction for this (signed/unsigned) sinonim instruction.
			if(is_r_supported(get_r_func(act_inst))){
				if(change_order_regs){
					printf("Applying change order registers to: 0x%08x -> ",act_inst);
					if(is_conmutative(get_r_func(act_inst))){		
						printf("Changed by 0x%08x \n",set_r_rs(act_inst,get_r_rd(act_inst)));
						act_inst = set_r_rs(act_inst,get_r_rd(act_inst));
					}
					else printf("Not changed due to lack of conmutative property\n\n");
				}
				if(change_instruct){
					printf("Applying Sustitute Instruction to: 0x%08x -> ",act_inst);
					if(get_r_func(act_inst)%2==0){
						printf("Changed by 0x%08x \n",replace_instruction(act_inst,get_r_func(act_inst)+1));
						act_inst = set_r_func(act_inst,get_r_func(act_inst)+1);
					}
					else{
						printf("Changed by 0x%08x \n",set_r_func(act_inst,get_r_func(act_inst)-1));
						act_inst = set_r_func(act_inst,get_r_func(act_inst)-1);
					}
				}
				else printf("Any changes kind of changes are applicated to actual instruction 0x%08x",act_inst); 
				printf("\n\n-------------------------------------------------\n\n");
			}
		}
		new_shellcode[i] = act_inst;
	}
}

// Code transformer is called to make processes of code mutation, you could contribute :P //
void code_transformer(int* instructions,int* new_shellcode,int num_inst){}
// End of stage of process //

/** END OF DEFINITIONS **/

/** __START **/
int main(int argc, char **argv)
{
	if(argc<=1 || argc>2){ perror("Not args or not enough, filename of file with opcodes it's only needed :(");exit(1); }
	srand(time(NULL));
	FILE *fd;
	fd = fopen(argv[1],"r");
	if(!fd){ perror("Cannot open file :("); exit(1); }
	int num_instructions = 0x00;
	fscanf(fd,"%i",&num_instructions); // Read number of instructions from file (first line from it)
	int *instructions  = (int*)malloc(num_instructions*sizeof(int));
	int *new_shellcode = (int*)malloc(num_instructions*sizeof(int)*MULTIPLY_FACTOR);
	read_instructions(instructions,fd,num_instructions);
	fclose(fd);
	analyze_code(instructions,new_shellcode,num_instructions);
	// Add more layers //
	show_shellcode(new_shellcode,num_instructions);
	free(num_instructions);
	free(new_shellcode);
	return 0;
}
/** .END **/


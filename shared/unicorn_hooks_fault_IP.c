#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include "unicorn_engine.h"
#include "unicorn_consts.h"
#include "configuration.h"
#include "state.h"
#include "structs.h"
#include "utils.h"
#include "fileio.h"

void do_the_IP_fault(uc_engine* uc, current_run_state_t* current_run_state,uint64_t address,uint64_t size)
{
    uint64_t pc_value=0;
    uc_reg_read(uc,binary_file_details->my_pc_reg,&pc_value);       // read it

    uint8_t* instruction_original=MY_STACK_ALLOC(sizeof(uint8_t)*(size+1));
    uc_mem_read(uc,address,instruction_original,size);

    fprintf_output(current_run_state->file_fprintf, "Skipped instruction            :  ");
    for (int i=0;i<size;i++)
    {
        fprintf(current_run_state->file_fprintf,"%02x ",instruction_original[i]);
    }

    if (current_run_state->display_disassembly && binary_file_details->my_cs_arch != MY_CS_ARCH_NONE)
    {
        // Can be turned off to save time - although I've not done the time calculations to see if it saves much time
        disassemble_instruction_and_print(current_run_state->file_fprintf,instruction_original,size); 
    }
    else
    {
        fprintf(current_run_state->file_fprintf,"\n");
    }

    //fault it
    pc_value=IP_fault_skip(current_run_state->fault_rule.operation, pc_value, size);

    uc_reg_write(uc,binary_file_details->my_pc_reg,&pc_value);      // write it

    if (current_run_state->run_state != FAULTED_rs)
    {
        // set the address where this fault occurred
        // this function might be called repeatedly if we skip multiple instructions,
        // we set the faulted address only for the first instruction.
        current_run_state->fault_rule.faulted_address=address;
    }

    // we've done the fault - so set faulting_mode to faulted!!
    current_run_state->run_state=FAULTED_rs;
    
    // we have to increase the count because we're skipping an instruction.
    current_run_state->instruction_count++;
}

void do_consecutive_IP_faults(uc_engine* uc, current_run_state_t* current_run_state, uint64_t start_address) {
    uint64_t pc_value=0;
    uc_reg_read(uc,binary_file_details->my_pc_reg,&pc_value);

    fprintf_output(current_run_state->file_fprintf, "Fault Address                  :  0x%" PRIx64 "\n",start_address);
    fprintf_output(current_run_state->file_fprintf, "Original IP                    :  0x%" PRIx64 "\n",pc_value);

    uint64_t size;
    uint64_t address_to_fault = start_address;
    uint64_t instruction_number = current_run_state->fault_rule.instruction;
    for (uint64_t i = 0; i < current_run_state->fault_rule.mask; i++) {
        // Skip instructions one by one until you reach the mask value.
        size = current_run_state->line_details_array[instruction_number].size;
        do_the_IP_fault(uc, current_run_state,address_to_fault,size);
        address_to_fault = address_to_fault + size;
        instruction_number++;
    }

    uc_reg_read(uc,binary_file_details->my_pc_reg,&pc_value);
    fprintf_output(current_run_state->file_fprintf, "Updated IP                     :  0x%" PRIx64 "\n",pc_value);
}


void hook_lifespan_repeat_IP(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;
    fault_rule_t* this_fault=&current_run_state->fault_rule;
    uint64_t fault_at_instruction=this_fault->instruction;
    uint64_t fault_address=current_run_state->line_details_array[fault_at_instruction].address;
    fault_address=thumb_check_address(fault_address);

    if (this_fault->instruction == current_run_state->instruction_count )
    {
        return;         // The repeated faults start AFTER the faulted address.
    }
    fprintf_output(current_run_state->file_fprintf,"Lifespan skip repeat countdown: %lu. (0x%" PRIx64 ") %" PRId64 "\n",this_fault->lifespan.count,address,current_run_state->instruction_count);
    
    this_fault->lifespan.live_counter--; 

    do_consecutive_IP_faults(uc, current_run_state, fault_address);

    if (this_fault->lifespan.live_counter == 0)
    {
        // delete this current hook
        my_uc_hook_del("hk_fault_lifespan",uc, current_run_state->hk_fault_lifespan,current_run_state);
        current_run_state->hk_fault_lifespan=0;
    }
}

void hook_code_fault_it_IP(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    current_run_state_t *current_run_state=(current_run_state_t *)user_data;

#ifdef DEBUG
        printf_debug("hook_code_fault_it_IP. Address 0x%" PRIx64 ". Count: %li\n", address, current_run_state->instruction_count);
#endif
    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    if (current_run_state->run_state == FAULTED_rs)
    {
        // Don't fault it more than once.
        return;
    }
    
    if (current_run_state->fault_rule.instruction != current_run_state->instruction_count)
    {
        // only fault the specific instruction
        return;
    }

    do_consecutive_IP_faults(uc, current_run_state, address);

    // Check for equivalences
    if (current_run_state->stop_on_equivalence)
    {
        my_uc_hook_add("hk_equivalent", uc, &current_run_state->hk_equivalent, UC_HOOK_CODE, hook_code_equivalent, current_run_state, 1, 0);
    }

    fault_rule_t *this_fault=&current_run_state->fault_rule;
    if (this_fault->lifespan.count != 0)
    {
        this_fault->lifespan.live_counter=this_fault->lifespan.count;
        if (this_fault->lifespan.mode == eREVERT_lsm)
        {
            fprintf_output(current_run_state->file_fprintf, "Note: You can't revert a skip instruction. Ignored.\n");
        }
        if (this_fault->lifespan.mode == eREPEAT_lsm)
        {
            fprintf_output(current_run_state->file_fprintf, "Note: repeating this fault %lu times.\n",this_fault->lifespan.count);
            my_uc_hook_add("hk_fault_lifespan(IP)", uc, &current_run_state->hk_fault_lifespan, UC_HOOK_CODE, hook_lifespan_repeat_IP, current_run_state, address, address);
        }
    }

    // We don't have to restart with IP  - the code isn't changing - just the instruction pointer.
    delete_hook_code_fault_it(uc, current_run_state); 
}

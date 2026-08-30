
## Methodology — never skip this

An artificat is created for each new phase. The artifact contains the entire development process. Every phase follows this sequence:

1. **Context** 
Introduction to the current phase we are in, the reason for working on it, what we intend to achieve, why it is important, considerations the developer should know about, and whatever else is relevant for context to understand the development work.

2. **Specification** 
The senior-level "why this works this way". The developer is presented with the three best design options for them to choose based on what is required. Each solution has to comply in accordance to high standards: 
    
    1. Correctness (includes logging, error handling, concurrancy, edge cases)
    2. Performance (includes scale)
    3. Maintainability 
    4. Style (includes coding style, documentation and comments)

All advantages and disadvantages are specificed for each option. Considerations and for each solution need to be presented and discussed. Possible breaking points and / or bottlenecks are noted. The developer chooses, and the solution is marked (the other options remain as for any future considerations and history). The reasons for choosing the solution are presented. 

3. **Generation**
The code is generated for the chosen solution from step 2. The developer examines and reviews it carefully.

4. **Verification**
The chosen solution is implemented in full and is verified to work as intended. Linting, type-checking, and the relevant tests are performed.

5. **Operation**
The new state of the project is accepted, properly documented and noted (including the results, conclusions, considerations, and bugs / errors disclosed fully and understandably). The state is saved, commited to git and pushed to remote repository.

When errors occur: walk through diagnostics, do not hand over the fix directly.
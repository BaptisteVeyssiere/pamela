NAME	= pamela.so

RM	= rm -rf

CC	= gcc

LD	= ld -x --shared

MKDIR	= mkdir -p

SRC	= src/pamela.c

SRCDIR	= src

OBJDIR	= obj

SECURITYDIR	= /lib/security

OBJ	= $(SRC:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CFLAGS	= -Iinclude -fPIC -W -Wextra -Wall -Werror

$(NAME) : $(OBJ)
	@$(LD) -o $(SECURITYDIR)/$(NAME) $(OBJ)
	@echo "Linking complete !"

$(OBJ) : $(OBJDIR)/%.o : $(SRCDIR)/%.c
	@$(MKDIR) $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully !"

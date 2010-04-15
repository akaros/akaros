#include <vcore.h>
#include <mcs.h>
#include <arch/atomic.h>
#include <string.h>
#include <stdlib.h>

// MCS locks
void mcs_lock_init(mcs_lock_t* lock)
{
	memset(lock,0,sizeof(mcs_lock_t));
}

static inline mcs_lock_qnode_t* mcs_qnode_swap(mcs_lock_qnode_t** addr, mcs_lock_qnode_t* val)
{
	return (mcs_lock_qnode_t*)atomic_swap((int*)addr,(int)val);
}

void mcs_lock_lock(mcs_lock_t* lock)
{
	mcs_lock_qnode_t* qnode = &lock->qnode[vcore_id()];
	qnode->next = 0;
	mcs_lock_qnode_t* predecessor = mcs_qnode_swap(&lock->lock,qnode);
	if(predecessor)
	{
		qnode->locked = 1;
		predecessor->next = qnode;
		while(qnode->locked);
	}
}

void mcs_lock_unlock(mcs_lock_t* lock)
{
	mcs_lock_qnode_t* qnode = &lock->qnode[vcore_id()];
	if(qnode->next == 0)
	{
		mcs_lock_qnode_t* old_tail = mcs_qnode_swap(&lock->lock,0);
		if(old_tail == qnode)
			return;

		mcs_lock_qnode_t* usurper = mcs_qnode_swap(&lock->lock,old_tail);
		while(qnode->next == 0);
		if(usurper)
			usurper->next = qnode->next;
		else
			qnode->next->locked = 0;
	}
	else
		qnode->next->locked = 0;
}

// MCS dissemination barrier!
int mcs_barrier_init(mcs_barrier_t* b, size_t np)
{
	if(np > max_vcores())
		return -1;
	b->allnodes = (mcs_dissem_flags_t*)malloc(np*sizeof(mcs_dissem_flags_t));
	memset(b->allnodes,0,np*sizeof(mcs_dissem_flags_t));
	b->nprocs = np;

	b->logp = (np & (np-1)) != 0;
	while(np >>= 1)
		b->logp++;

	size_t i,k;
	for(i = 0; i < b->nprocs; i++)
	{
		b->allnodes[i].parity = 0;
		b->allnodes[i].sense = 1;

		for(k = 0; k < b->logp; k++)
		{
			size_t j = (i+(1<<k)) % b->nprocs;
			b->allnodes[i].partnerflags[0][k] = &b->allnodes[j].myflags[0][k];
			b->allnodes[i].partnerflags[1][k] = &b->allnodes[j].myflags[1][k];
		} 
	}

	return 0;
}

void mcs_barrier_wait(mcs_barrier_t* b, size_t pid)
{
	mcs_dissem_flags_t* localflags = &b->allnodes[pid];
	size_t i;
	for(i = 0; i < b->logp; i++)
	{
		*localflags->partnerflags[localflags->parity][i] = localflags->sense;
		while(localflags->myflags[localflags->parity][i] != localflags->sense);
	}
	if(localflags->parity)
		localflags->sense = 1-localflags->sense;
	localflags->parity = 1-localflags->parity;
}


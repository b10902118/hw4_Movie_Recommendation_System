#ifdef THREAD
#include "header.h"
#include <asm-generic/errno.h>
#include <bits/types/sigset_t.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define BASECASE 4000 // max 512 threads

movie_profile *movies[MAX_MOVIES];
unsigned int num_of_movies = 0;
unsigned int num_of_reqs = 0;
request *reqs[MAX_REQ];

void initialize(FILE *fp);
request *read_request();
// Global request queue and pointer to front of queue
// TODO: critical section to protect the global resources
// int front = -1;
/* Note that the maximum number of processes per workstation user is
 * 512. * We recommend that using about <256 threads is enough in this
 * homework. */
/*
pthread_t tid[MAX_CPU][MAX_THREAD]; // tids for multithread

#ifdef PROCESS
pid_t pid[MAX_CPU][MAX_THREAD]; // pids for multiprocess
#endif
*/
// mutex
// pthread_mutex_t lock;

/*
int pop();

int pop() {
    front += 1;
    return front;
}
*/
typedef struct {
    int id;
    char **title;
    double *score;
    int sz;
} Data;

Data *filter(int n) {
    char **title = malloc(num_of_movies * sizeof(char *));
    double *score = calloc(num_of_movies, sizeof(double));
    int sz = 0;
    // filter by keyword
    if (reqs[n]->keywords[0] == '*') {
        for (int i = 0; i < num_of_movies; i++) {
            title[i] = movies[i]->title;
            for (int j = 0; j < NUM_OF_GENRE; ++j) {
                if (reqs[n]->profile[j] != 0)
                    score[i] +=
                    movies[i]->profile[j] * reqs[n]->profile[j];
            }
        }
        sz = num_of_movies;
    }
    else {
        for (int i = 0; i < num_of_movies; ++i) {
            if (strstr(movies[i]->title, reqs[n]->keywords)) {
                title[sz] = movies[i]->title;
                for (int j = 0; j < NUM_OF_GENRE; ++j) {
                    if (reqs[n]->profile[j] != 0)
                        score[sz] +=
                        movies[i]->profile[j] * reqs[n]->profile[j];
                }
                ++sz;
            }
        }
    }
    Data *ret = malloc(sizeof(Data));
    *ret = (Data){n, title, score, sz};
    return ret;
}

char **start[MAX_REQ];
char *tmp_str[MAX_REQ][MAX_MOVIES];
double tmp_pt[MAX_REQ][MAX_MOVIES];
void mg(Data *a, Data larg, Data rarg) {
    int li = 0, ri = 0, led = larg.sz, red = rarg.sz;
    int offset = a->title - start[a->id];
    char **str = &tmp_str[a->id][offset];
    double *pt = &tmp_pt[a->id][offset];
    int cur = 0;
    while (li != led && ri != red) {
        if (larg.score[li] > rarg.score[ri]) {
            str[cur] = larg.title[li];
            pt[cur] = larg.score[li];
            ++li;
        }
        else if (rarg.score[ri] > larg.score[li]) {
            str[cur] = rarg.title[ri];
            pt[cur] = rarg.score[ri];
            ++ri;
        }
        else {
            if (strcmp(larg.title[li], rarg.title[ri]) < 0) {
                str[cur] = larg.title[li];
                pt[cur] = larg.score[li];
                ++li;
            }
            else {
                str[cur] = rarg.title[ri];
                pt[cur] = rarg.score[ri];
                ++ri;
            }
        }
        ++cur;
    }
    if (li != led) {
        for (int i = 1; led - i >= li; ++i) {
            a->title[a->sz - i] = larg.title[led - i];
            a->score[a->sz - i] = larg.score[led - i];
        }
    }
    for (int i = 0; i < cur; ++i) {
        a->title[i] = str[i];
        a->score[i] = pt[i];
    }
    /*
    memcpy(a->title, str, cur*sizeof(char*));
    memcpy(a->score, pt, cur*sizeof(double));
    */
}
void *merge(void *v) {
    Data *a = (Data *)v;
    int mid = a->sz / 2;
    Data larg = {a->id, a->title, a->score, mid},
         rarg = {a->id, a->title + mid, a->score + mid, a->sz - mid};
    if (a->sz < BASECASE) {
        if (a->sz < 2500) {
            sort(a->title, a->score, a->sz);
            return (void *)0;
        }
        sort(larg.title, larg.score, larg.sz); // heap overflow
        sort(rarg.title, rarg.score, rarg.sz);
        mg(a, larg, rarg);
        // printf("%d OK\n", a->sz);
        return (void *)0;
    }
    pthread_t tl, tr;
    pthread_create(&tl, NULL, merge, (void *)&larg);
    pthread_create(&tr, NULL, merge, (void *)&rarg);
    pthread_join(tl, NULL);
    pthread_join(tr, NULL);
    mg(a, larg, rarg);
    return (void *)0;
}

void *handler(void *v) {
    int n = (int)v;
    Data *p = filter(n);
    if (p->sz > 0) {
        if (p->sz < 5000) sort(p->title, p->score, p->sz);
        else {
            start[n] = p->title;
            pthread_t tid;
            int mid = p->sz / 2;
            Data larg = {n, p->title, p->score, mid},
                 rarg = {n, p->title + mid, p->score + mid,
                         p->sz - mid};
            pthread_create(&tid, NULL, merge, (void *)&rarg);
            merge((void *)&larg);
            pthread_join(tid, NULL);
            mg(p, larg, rarg);
        }
        char name[20];
        sprintf(name, "%dt.out", reqs[n]->id);
        FILE *fp = fopen(name, "w");
        for (int i = 0; i < p->sz; ++i)
            fprintf(fp, "%s\n", p->title[i]);
        fclose(fp);
    }
    // for(int i=0;i<p->sz;++i) free(p->title[i]); //dangerous
    free(p->title);
    free(p->score);
    free(p);
    return (void *)0;
}
int main(int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "usage: ./tserver\n");
        exit(-1);
    }

    umask(0);
    FILE *fp;

    if ((fp = fopen("./data/movies.txt", "r")) == NULL) {
        ERR_EXIT("fopen");
    }
    initialize(fp);
    assert(fp != NULL);
    fclose(fp);
    pthread_t tid[MAX_REQ];
    /*
for (int i = 0; i < num_of_reqs; ++i) {
    pthread_create(&tid[i], NULL, handler, (void *)i);
}
for (int i = 0; i < num_of_reqs; ++i)
            pthread_join(tid[i], NULL);
    */
    for (int i = 0; i < num_of_reqs; i += 16) {
        for (int j = 0; j < 16 && i + j < num_of_reqs; ++j)
            pthread_create(&tid[i + j], NULL, handler, (void *)i + j);
        for (int j = 0; j < 16 && i + j < num_of_reqs; ++j)
            pthread_join(tid[i + j], NULL);
    }
    return 0;
}
#endif

#ifdef PROCESS
#include "header.h"
#include <asm-generic/errno.h>
#include <bits/types/sigset_t.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BASECASE 4000 // max 512 threads

movie_profile *movies[MAX_MOVIES];
unsigned int num_of_movies = 0;
unsigned int num_of_reqs = 0;
request *reqs[MAX_REQ];

void initialize(FILE *fp);
request *read_request();
// Global request queue and pointer to front of queue
// TODO: critical section to protect the global resources
// int front = -1;
/* Note that the maximum number of processes per workstation user is
 * 512. * We recommend that using about <256 threads is enough in this
 * homework. */
/*
pthread_t tid[MAX_CPU][MAX_THREAD]; // tids for multithread

#ifdef PROCESS
pid_t pid[MAX_CPU][MAX_THREAD]; // pids for multiprocess
#endif
*/
// mutex
// pthread_mutex_t lock;

/*
int pop();

int pop() {
    front += 1;
    return front;
}
*/
typedef struct {
    int id;
    char **title;
    double *score;
    int sz;
} Data;

Data *filter(int n) {
    char **title =
    mmap(NULL, num_of_movies * sizeof(char *), PROT_READ | PROT_WRITE,
         MAP_ANON | MAP_SHARED, -1, 0);
    double *score =
    mmap(NULL, num_of_movies * sizeof(double), PROT_READ | PROT_WRITE,
         MAP_ANON | MAP_SHARED, -1, 0);
    int sz = 0;
    // filter by keyword
    if (reqs[n]->keywords[0] == '*') {
        for (int i = 0; i < num_of_movies; i++) {
            title[i] = mmap(0, MAX_LEN + 1, PROT_READ | PROT_WRITE,
                            MAP_ANON | MAP_SHARED, -1, 0);
            strcpy(title[i], movies[i]->title);
            for (int j = 0; j < NUM_OF_GENRE; ++j) {
                if (reqs[n]->profile[j] != 0)
                    score[i] +=
                    movies[i]->profile[j] * reqs[n]->profile[j];
            }
        }
        sz = num_of_movies;
    }
    else {
        for (int i = 0; i < num_of_movies; ++i) {
            if (strstr(movies[i]->title, reqs[n]->keywords)) {
                title[sz] =
                mmap(0, MAX_LEN + 1, PROT_READ | PROT_WRITE,
                     MAP_ANON | MAP_SHARED, -1, 0);
                strcpy(title[sz], movies[i]->title);
                for (int j = 0; j < NUM_OF_GENRE; ++j) {
                    if (reqs[n]->profile[j] != 0)
                        score[sz] +=
                        movies[i]->profile[j] * reqs[n]->profile[j];
                }
                ++sz;
            }
        }
    }
    // Data *ret = mmap(0, sizeof(Data), PROT_WRITE|PROT_READ,
    // MAP_SHARED|MAP_ANON, -1, 0);
    Data *ret = malloc(sizeof(Data));
    *ret = (Data){n, title, score, sz};
    return ret;
}

char **start[MAX_REQ];
char *tmp_str[MAX_REQ][MAX_MOVIES];
double tmp_pt[MAX_REQ][MAX_MOVIES];
void mg(Data *a, Data larg, Data rarg) {
    int li = 0, ri = 0, led = larg.sz, red = rarg.sz;
    int offset = a->title - start[a->id];
    char **str = &tmp_str[a->id][offset];
    double *pt = &tmp_pt[a->id][offset];
    int cur = 0;
    while (li != led && ri != red) {
        if (larg.score[li] > rarg.score[ri]) {
            str[cur] = larg.title[li];
            pt[cur] = larg.score[li];
            ++li;
        }
        else if (rarg.score[ri] > larg.score[li]) {
            str[cur] = rarg.title[ri];
            pt[cur] = rarg.score[ri];
            ++ri;
        }
        else {
            if (strcmp(larg.title[li], rarg.title[ri]) < 0) {
                str[cur] = larg.title[li];
                pt[cur] = larg.score[li];
                ++li;
            }
            else {
                str[cur] = rarg.title[ri];
                pt[cur] = rarg.score[ri];
                ++ri;
            }
        }
        ++cur;
    }
    if (li != led) {
        for (int i = 1; led - i >= li; ++i) {
            a->title[a->sz - i] = larg.title[led - i];
            a->score[a->sz - i] = larg.score[led - i];
        }
    }
    for (int i = 0; i < cur; ++i) {
        a->title[i] = str[i];
        a->score[i] = pt[i];
    }
    /*
    memcpy(a->title, str, cur*sizeof(char*));
    memcpy(a->score, pt, cur*sizeof(double));
    */
}
void *merge(void *v) {
    Data *a = (Data *)v;
    int mid = a->sz / 2;
    Data larg = {a->id, a->title, a->score, mid},
         rarg = {a->id, a->title + mid, a->score + mid, a->sz - mid};
    if (a->sz < BASECASE) {
        // if (a->sz < 2500) {
        int offset = a->title - start[a->id];
        char **str = &tmp_str[a->id][offset];
        double *pt = &tmp_pt[a->id][offset];
        for (int i = 0; i < a->sz; ++i) {
            str[i] = a->title[i];
        }
        sort(a->title, a->score, a->sz);
        for (int i = 0; i < a->sz; ++i) {
            strcpy(str[i], a->title[i]);
            a->title[i] = str[i];
        }
        return (void *)0;
        /*}

        int offset = larg.title - start[larg.id];
        char **str = &tmp_str[larg.id][offset];
        for (int i = 0; i < larg.sz; ++i) {
            str[i] = larg.title[i];
        }
        sort(larg.title, larg.score, larg.sz); // heap overflow
        for (int i = 0; i < larg.sz; ++i) {
            strcpy(str[i], larg.title[i]);
            larg.title[i] = str[i];
        }
        offset = rarg.title - start[rarg.id];
        str = &tmp_str[rarg.id][offset];
        for (int i = 0; i < rarg.sz; ++i) {
            str[i] = rarg.title[i];
        }
        sort(rarg.title, rarg.score, rarg.sz);
        for (int i = 0; i < rarg.sz; ++i) {
            strcpy(str[i], rarg.title[i]);
            rarg.title[i] = str[i];
        }
        mg(a, larg, rarg);
        return (void *)0;
                */
    }
    pid_t chd = fork();
    if (chd < 0) ERR_EXIT("fork");
    else if (chd == 0) {
        merge(&rarg);
        _exit(0);
    }
    else {
        merge(&larg);
        waitpid(chd, NULL, 0);
    }
    mg(a, larg, rarg);
    return (void *)0;
}

int main(int argc, char *argv[]) {
    if (argc != 1) {
        fprintf(stderr, "usage: ./pserver\n");
        exit(-1);
    }

    umask(0);
    FILE *fp;

    if ((fp = fopen("./data/movies.txt", "r")) == NULL)
        ERR_EXIT("fopen");
    initialize(fp);
    assert(fp != NULL);
    fclose(fp);

    pid_t pid[MAX_REQ];
    for (int i = 0; i < num_of_reqs; i += 16) {
        for (int j = 0; j < 16 && i + j < num_of_reqs; ++j) {
            // per request
            if ((pid[i + j] = fork()) < 0) ERR_EXIT("fork error");
            else if (pid[i + j] == 0) { // handler
                int n = i + j;
                Data *p = filter(n);
                if (p->sz > 0) {
                    // if (p->sz < 5000) sort(p->title, p->score,
                    // p->sz); else {
                    start[n] = p->title;
                    merge(p);
                    //}
                    char name[20];
                    sprintf(name, "%dp.out", reqs[n]->id);
                    FILE *fp = fopen(name, "w");
                    for (int i = 0; i < p->sz; ++i)
                        fprintf(fp, "%s\n", p->title[i]);
                    fclose(fp);
                }
                // for(int i=0;i<p->sz;++i) free(p->title[i]);
                // //dangerous
                munmap(p->title, p->sz * sizeof(char *));
                munmap(p->score, p->sz * sizeof(double));
                free(p);
                _exit(0);
            }
        }
        for (int j = 0; j < 16 && i + j < num_of_reqs; ++j)
            waitpid(pid[i + j], NULL, 0);
    }
    return 0;
}
#endif
/**=======================================
 * You don't need to modify following code *
 * But feel free if needed.                *
 =========================================**/

request *read_request() {
    int id;
    char buf1[MAX_LEN], buf2[MAX_LEN];
    char delim[2] = ",";

    char *keywords;
    char *token, *ref_pts;
    char *ptr;
    double ret, sum;

    scanf("%u %254s %254s", &id, buf1, buf2);
    keywords = malloc(sizeof(char) * strlen(buf1) + 1);
    if (keywords == NULL) {
        ERR_EXIT("malloc");
    }

    memcpy(keywords, buf1, strlen(buf1));
    keywords[strlen(buf1)] = '\0';

    double *profile = malloc(sizeof(double) * NUM_OF_GENRE);
    if (profile == NULL) {
        ERR_EXIT("malloc");
    }
    sum = 0;
    ref_pts = strtok(buf2, delim);
    for (int i = 0; i < NUM_OF_GENRE; i++) {
        ret = strtod(ref_pts, &ptr);
        profile[i] = ret;
        sum += ret * ret;
        ref_pts = strtok(NULL, delim);
    }

    // normalize
    sum = sqrt(sum);
    for (int i = 0; i < NUM_OF_GENRE; i++) {
        if (sum == 0) profile[i] = 0;
        else profile[i] /= sum;
    }

    request *r = malloc(sizeof(request));
    if (r == NULL) {
        ERR_EXIT("malloc");
    }

    r->id = id;
    r->keywords = keywords;
    r->profile = profile;

    return r;
}
/*=================initialize the dataset=================*/
void initialize(FILE *fp) {

    char chunk[MAX_LEN] = {0};
    char *token, *ptr;
    double ret, sum;
    int cnt = 0;

    assert(fp != NULL);

    // first row
    if (fgets(chunk, sizeof(chunk), fp) == NULL) {
        ERR_EXIT("fgets");
    }

    memset(movies, 0, sizeof(movie_profile *) * MAX_MOVIES);

    while (fgets(chunk, sizeof(chunk), fp) != NULL) {

        assert(cnt < MAX_MOVIES);
        chunk[MAX_LEN - 1] = '\0';

        const char delim1[2] = " ";
        const char delim2[2] = "{";
        const char delim3[2] = ",";
        unsigned int movieId;
        movieId = atoi(strtok(chunk, delim1));

        // title
        token = strtok(NULL, delim2);
        char *title = malloc(sizeof(char) * strlen(token) + 1);
        if (title == NULL) {
            ERR_EXIT("malloc");
        }

        // title.strip()
        memcpy(title, token, strlen(token) - 1);
        title[strlen(token) - 1] = '\0';

        // genres
        double *profile = malloc(sizeof(double) * NUM_OF_GENRE);
        if (profile == NULL) {
            ERR_EXIT("malloc");
        }

        sum = 0;
        token = strtok(NULL, delim3);
        for (int i = 0; i < NUM_OF_GENRE; i++) {
            ret = strtod(token, &ptr);
            profile[i] = ret;
            sum += ret * ret;
            token = strtok(NULL, delim3);
        }

        // normalize
        sum = sqrt(sum);
        for (int i = 0; i < NUM_OF_GENRE; i++) {
            if (sum == 0) profile[i] = 0;
            else profile[i] /= sum;
        }

        movie_profile *m = malloc(sizeof(movie_profile));
        if (m == NULL) {
            ERR_EXIT("malloc");
        }

        m->movieId = movieId;
        m->title = title;
        m->profile = profile;

        movies[cnt++] = m;
    }
    num_of_movies = cnt;

    // request
    scanf("%d", &num_of_reqs);
    assert(num_of_reqs <= MAX_REQ);
    for (int i = 0; i < num_of_reqs; i++) {
        reqs[i] = read_request();
    }
}
/*========================================================*/

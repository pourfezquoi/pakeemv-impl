#ifndef __TYPES_H__
#define __TYPES_H__


#define HS_API				//API Function's Flag
#define IN					//Parameter's IN Flag
#define OUT					//Parameter's OUT Flag




typedef unsigned char           T_U8,U8,uint8_t;
typedef char                    T_S8;
typedef unsigned short          T_U16,U16,uint16_t;
typedef short                   T_S16;
//typedef unsigned long			T_U32,U32,uint32_t;
typedef unsigned int			T_U32,U32,uint32_t;
typedef long                    T_S32;
typedef unsigned int			T_BOOL;
typedef long                    T_RESULT;
typedef void                    T_VOID;

        /*
typedef void                    T_VOID;
typedef unsigned char           T_U8;
typedef char                    T_S8;
typedef unsigned short          T_U16;
typedef short                   T_S16;
typedef unsigned int			T_U32;
typedef long                    T_S32;
typedef unsigned int			T_BOOL;
typedef long                    T_RESULT;
   */
   
//#define		__I     volatile             /*!< Defines 'read only' permissions                 */
#define		__O     volatile             /*!< Defines 'write only' permissions                */
#define		__IO    volatile             /*!< Defines 'read / write' permissions              */



#define min(a, b)					(((a)<(b))?(a):(b))
#define max(a, b)					(((a)>(b))?(a):(b))


#define HS_API				//API Function's Flag
#define IN					//Parameter's IN Flag
#define OUT					//Parameter's OUT Flag


#define	HS_FALSE				0
#define	HS_TRUE					1
#define	HS_NULL					0

#define RADIX_BITS		32
#define S16_MIN			(-32768)
#define S16_MAX			32767
#define U16_MAX			0xffff
#define S32_MIN			(-2147483647 - 1)
#define S32_MAX			2147483647
#define U32_MAX			0xffffffff

#define min(a, b)					(((a)<(b))?(a):(b))
#define max(a, b)					(((a)>(b))?(a):(b))


		
		
#endif

